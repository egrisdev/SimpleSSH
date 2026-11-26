using SimpleSSH.Core.Models;

namespace SimpleSSH.Core;

public sealed record TagGroup(string Tag, bool IsUntagged, IReadOnlyList<Connection> Connections);

/// <summary>
/// Builds the tree shown in the sidebar: one group per tag (alphabetical), connections sorted by
/// name inside each group. A connection with several tags appears under each of them; connections
/// without tags go into a trailing "Untagged" group.
/// </summary>
public static class TagGrouping
{
    public const string UntaggedLabel = "Untagged";

    public static IReadOnlyList<TagGroup> Build(IEnumerable<Connection> connections, string? filter = null)
    {
        var f = filter?.Trim();
        var byTag = new Dictionary<string, (string Display, List<Connection> Items)>(StringComparer.OrdinalIgnoreCase);
        var untagged = new List<Connection>();

        foreach (var c in connections)
        {
            if (c.Tags.Count == 0)
            {
                if (Matches(c, null, f)) untagged.Add(c);
                continue;
            }

            foreach (var tag in c.Tags)
            {
                if (!Matches(c, tag, f)) continue;
                if (!byTag.TryGetValue(tag, out var bucket))
                {
                    bucket = (tag, new List<Connection>());
                    byTag[tag] = bucket;
                }
                if (!bucket.Items.Contains(c)) bucket.Items.Add(c);
            }
        }

        var groups = byTag.Values
            .OrderBy(b => b.Display, NaturalStringComparer.Instance)
            .Select(b => new TagGroup(b.Display, false, Sort(b.Items)))
            .ToList();

        if (untagged.Count > 0) groups.Add(new TagGroup(UntaggedLabel, true, Sort(untagged)));
        return groups;
    }

    /// <summary>
    /// The tags after dragging a connection from one group to another (<c>null</c> = the Untagged group).
    /// Moving swaps <paramref name="from"/> for <paramref name="to"/>; copying (<paramref name="keepSource"/>) only
    /// adds <paramref name="to"/>. Dropping on Untagged removes every tag. Returns null when nothing would change.
    /// </summary>
    public static List<string>? RetagForDrop(IReadOnlyList<string> tags, string? from, string? to, bool keepSource)
    {
        List<string> result;
        if (to is null)
        {
            if (keepSource) return null; // "also untagged" means nothing
            result = new List<string>();
        }
        else
        {
            result = tags.ToList();
            if (!keepSource && from is not null) result.RemoveAll(t => string.Equals(t, from, StringComparison.OrdinalIgnoreCase));
            result.Add(to);
        }
        result = Connection.NormalizeTags(result);
        var unchanged = result.Count == tags.Count && result.Zip(tags).All(p => string.Equals(p.First, p.Second, StringComparison.OrdinalIgnoreCase));
        return unchanged ? null : result;
    }

    private static IReadOnlyList<Connection> Sort(IEnumerable<Connection> items) =>
        items.OrderBy(c => c.DisplayName, NaturalStringComparer.Instance)
             .ThenBy(c => c.Host, NaturalStringComparer.Instance)
             .ToList();

    /// <summary>Filter hits on name, host, username, notes, or the group's tag.</summary>
    private static bool Matches(Connection c, string? groupTag, string? filter)
    {
        if (string.IsNullOrEmpty(filter)) return true;
        bool Has(string? s) => s?.Contains(filter, StringComparison.OrdinalIgnoreCase) == true;
        return Has(c.Name) || Has(c.Host) || Has(c.Username) || Has(c.Notes) || Has(groupTag)
               || (groupTag is null && Has(UntaggedLabel));
    }
}
