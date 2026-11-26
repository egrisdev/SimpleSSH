namespace SimpleSSH.Core.Ssh;

/// <summary>Text pasted into a terminal.</summary>
public static class PasteText
{
    /// <summary>
    /// Removes control characters except tab and line breaks. Text copied from a web page can hide an escape sequence
    /// such as <c>ESC[201~</c>, which ends the shell's "bracketed paste" early, so the rest (a command and Enter) would
    /// run at once instead of waiting at the prompt. Also drops 8-bit controls (U+0080–U+009F, e.g. a one-byte CSI).
    /// </summary>
    public static string Clean(string text)
    {
        if (string.IsNullOrEmpty(text)) return "";
        var chars = new char[text.Length];
        int n = 0;
        foreach (var c in text)
        {
            if (c is '\t' or '\n' or '\r' || !(char.IsControl(c))) chars[n++] = c;
        }
        return n == text.Length ? text : new string(chars, 0, n);
    }
}
