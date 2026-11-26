namespace SimpleSSH.Core;

/// <summary>
/// Case-insensitive "natural" ordering so that sw-2 sorts before sw-10.
/// </summary>
public sealed class NaturalStringComparer : IComparer<string?>
{
    public static readonly NaturalStringComparer Instance = new();

    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y)) return 0;
        if (x is null) return -1;
        if (y is null) return 1;

        int i = 0, j = 0;
        while (i < x.Length && j < y.Length)
        {
            if (char.IsDigit(x[i]) && char.IsDigit(y[j]))
            {
                int si = i, sj = j;
                while (si < x.Length && x[si] == '0') si++;
                while (sj < y.Length && y[sj] == '0') sj++;
                int ei = si, ej = sj;
                while (ei < x.Length && char.IsDigit(x[ei])) ei++;
                while (ej < y.Length && char.IsDigit(y[ej])) ej++;

                int lenX = ei - si, lenY = ej - sj;
                if (lenX != lenY) return lenX.CompareTo(lenY);
                int cmp = string.CompareOrdinal(x, si, y, sj, lenX);
                if (cmp != 0) return cmp;
                i = ei; j = ej;
                continue;
            }

            int c = char.ToUpperInvariant(x[i]).CompareTo(char.ToUpperInvariant(y[j]));
            if (c != 0) return c;
            i++; j++;
        }

        int rest = (x.Length - i).CompareTo(y.Length - j);
        if (rest != 0) return rest;
        // Equal "naturally" (e.g. differ only in case or leading zeros): make the order deterministic.
        int ci = string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
        return ci != 0 ? ci : string.CompareOrdinal(x, y);
    }
}
