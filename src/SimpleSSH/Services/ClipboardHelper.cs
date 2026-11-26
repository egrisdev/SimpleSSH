using System.Runtime.InteropServices;
using System.Windows;

namespace SimpleSSH.Services;

/// <summary>The clipboard is a shared resource that is sometimes briefly locked by other apps; retry a few times.</summary>
internal static class ClipboardHelper
{
    public static void SetText(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Clipboard.SetText(text);
                return;
            }
            catch (COMException)
            {
                Thread.Sleep(20);
            }
        }
    }

    /// <summary>
    /// Copies a secret: kept out of Windows clipboard history and cloud clipboard, and cleared after
    /// <paramref name="clearAfter"/> if it is still on the clipboard then.
    /// </summary>
    public static bool SetSecret(string text, TimeSpan clearAfter)
    {
        var data = new DataObject();
        data.SetText(text);
        data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[4]));
        data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
        data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Clipboard.SetDataObject(data, copy: true);
                var timer = new System.Windows.Threading.DispatcherTimer { Interval = clearAfter };
                timer.Tick += (_, _) =>
                {
                    timer.Stop();
                    try
                    {
                        if (Clipboard.ContainsText() && Clipboard.GetText() == text) Clipboard.Clear();
                    }
                    catch (COMException) { }
                };
                timer.Start();
                return true;
            }
            catch (COMException)
            {
                Thread.Sleep(20);
            }
        }
        return false;
    }

    public static string GetText()
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                return Clipboard.ContainsText() ? Clipboard.GetText() : "";
            }
            catch (COMException)
            {
                Thread.Sleep(20);
            }
        }
        return "";
    }
}
