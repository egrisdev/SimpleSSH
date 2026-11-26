using SimpleSSH.Core;
using SimpleSSH.Core.Models;

namespace SimpleSSH.Tests;

public sealed class TagGroupingTests
{
    private static Connection C(string name, params string[] tags) =>
        new() { Name = name, Host = name + ".lan", Tags = tags.ToList() };

    [Fact]
    public void Groups_AreAlphabetical_UntaggedLast_ConnectionsSortedNaturally()
    {
        var groups = TagGrouping.Build(new[]
        {
            C("web-10", "servers"),
            C("sw-10", "Switches"),
            C("web-2", "servers"),
            C("printer"),
            C("sw-2", "Switches"),
            C("fw-1", "firewalls"),
        });

        Assert.Equal(new[] { "firewalls", "servers", "Switches", "Untagged" }, groups.Select(g => g.Tag));
        Assert.True(groups[^1].IsUntagged);
        Assert.Equal(new[] { "web-2", "web-10" }, groups[1].Connections.Select(c => c.Name));
        Assert.Equal(new[] { "sw-2", "sw-10" }, groups[2].Connections.Select(c => c.Name));
    }

    [Fact]
    public void MultiTaggedConnection_AppearsUnderEachTag()
    {
        var both = C("core", "Switches", "Core");
        var groups = TagGrouping.Build(new[] { both });
        Assert.Equal(new[] { "Core", "Switches" }, groups.Select(g => g.Tag));
        Assert.All(groups, g => Assert.Same(both, Assert.Single(g.Connections)));
    }

    [Fact]
    public void TagsDifferingOnlyByCase_ShareAGroup()
    {
        var groups = TagGrouping.Build(new[] { C("a", "Servers"), C("b", "servers") });
        var g = Assert.Single(groups);
        Assert.Equal(2, g.Connections.Count);
    }

    [Fact]
    public void Filter_MatchesNameHostOrTag()
    {
        var all = new[] { C("alpha", "servers"), C("beta", "Switches"), C("gamma") };

        Assert.Equal(new[] { "alpha" }, TagGrouping.Build(all, "alp").SelectMany(g => g.Connections).Select(c => c.Name));
        Assert.Equal(new[] { "beta" }, TagGrouping.Build(all, "switch").SelectMany(g => g.Connections).Select(c => c.Name));
        Assert.Equal(new[] { "gamma" }, TagGrouping.Build(all, "gamma.lan").SelectMany(g => g.Connections).Select(c => c.Name));
        Assert.Empty(TagGrouping.Build(all, "nothing-matches"));
    }

    [Theory]
    [InlineData("Switches", "Switches", "Windows Servers", false, "Windows Servers")]
    [InlineData("Switches,Core", "Switches", "Windows Servers", false, "Core,Windows Servers")]
    [InlineData("Switches", "Switches", "Windows Servers", true, "Switches,Windows Servers")]
    [InlineData("Switches,Core", "Switches", "Core", false, "Core")]
    [InlineData("", null, "Servers", false, "Servers")]
    [InlineData("", null, "Servers", true, "Servers")]
    [InlineData("Switches,Core", "Switches", null, false, "")]
    public void RetagForDrop(string tags, string? from, string? to, bool keepSource, string expected)
    {
        var result = TagGrouping.RetagForDrop(Connection.ParseTags(tags), from, to, keepSource);
        Assert.NotNull(result);
        Assert.Equal(Connection.ParseTags(expected), result);
    }

    [Theory]
    [InlineData("Switches", "Switches", "switches", false)] // same group, other spelling
    [InlineData("Switches,Core", "Switches", "Core", true)] // already has it
    [InlineData("Switches", "Switches", null, true)]        // "copy to Untagged"
    [InlineData("", null, null, false)]                     // Untagged onto Untagged
    public void RetagForDrop_NoChange(string tags, string? from, string? to, bool keepSource)
    {
        Assert.Null(TagGrouping.RetagForDrop(Connection.ParseTags(tags), from, to, keepSource));
    }

    [Fact]
    public void NaturalComparer_Orders()
    {
        var input = new[] { "sw10", "SW2", "sw1", "a", "sw02", "B" };
        var sorted = input.OrderBy(s => s, NaturalStringComparer.Instance).ToArray();
        Assert.Equal(new[] { "a", "B", "sw1", "sw02", "SW2", "sw10" }, sorted);
    }
}
