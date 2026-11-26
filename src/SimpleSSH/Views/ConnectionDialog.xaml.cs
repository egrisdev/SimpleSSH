using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SimpleSSH.Core;
using SimpleSSH.Core.Models;
using SimpleSSH.Core.Ssh;

namespace SimpleSSH.Views;

public partial class ConnectionDialog : Window
{
    private const string AddTagPlaceholder = "Add tag…";
    private readonly Connection _working;
    /// <summary>A key kept inside SimpleSSH (pasted, or made by Switch to key login), instead of a key file.</summary>
    private string? _storedKey;
    private string? _storedPublicKey;
    private bool _loading;

    /// <param name="existing">Connection to edit (a copy is edited), or null for a new one.</param>
    /// <param name="allTags">Known tags for the quick-add dropdown.</param>
    /// <param name="defaultTag">Tag pre-filled for new connections (e.g. the selected group).</param>
    public ConnectionDialog(Connection? existing, IEnumerable<string> allTags, string? defaultTag = null)
    {
        InitializeComponent();
        _working = existing?.Clone() ?? new Connection();
        Title = existing is null ? "New connection" : $"Edit connection – {existing.DisplayName}";

        NameBox.Text = _working.Name;
        HostBox.Text = _working.Host;
        PortBox.Text = _working.Port.ToString();
        UserBox.Text = _working.Username;
        PasswordBox.Password = _working.Password ?? "";
        KeyPathBox.Text = _working.PrivateKeyPath ?? "";
        PassphraseBox.Password = _working.PrivateKeyPassphrase ?? "";
        _storedKey = _working.PrivateKey;
        _storedPublicKey = _working.PublicKey;
        UpdateKeyUi();
        TagsBox.Text = existing is null && !string.IsNullOrWhiteSpace(defaultTag)
            ? defaultTag
            : Connection.FormatTags(_working.Tags);
        NotesBox.Text = _working.Notes ?? "";
        TunnelsBox.Text = string.Join(Environment.NewLine, _working.Tunnels ?? new List<string>());
        ProxyBox.Text = _working.Proxy ?? "";
        CopyOnSelectBox.IsChecked = _working.CopiesOnSelect;
        AdvancedExpander.IsExpanded = TunnelsBox.Text.Length > 0 || ProxyBox.Text.Length > 0 || !_working.CopiesOnSelect;
        _loading = true; // keep the saved port (e.g. SSH on 443)
        (_working.Protocol switch
        {
            ConnectionProtocol.Rdp => RdpRadio,
            ConnectionProtocol.Console => ConsoleRadio,
            ConnectionProtocol.Web => WebRadio,
            _ => SshRadio,
        }).IsChecked = true;
        _loading = false;
        ApplyProtocol();

        ExistingTags.Items.Add(AddTagPlaceholder);
        foreach (var t in allTags) ExistingTags.Items.Add(t);
        ExistingTags.SelectedIndex = 0;
        ExistingTags.IsEnabled = ExistingTags.Items.Count > 1;

        SecurityNote.Text = (Services.AppServices.Connections.Vault is null
                ? "Passwords and passphrases are encrypted with your Windows account (DPAPI): only you, signed in to Windows, can read them. "
                : "Passwords and passphrases are encrypted with your security key and your Windows account. ") +
            "Leave the password empty to be asked at connect time instead.";

        Loaded += (_, _) => (string.IsNullOrEmpty(HostBox.Text) ? HostBox : NameBox).Focus();
    }

    /// <summary>The edited connection (same Id as the original when editing).</summary>
    public Connection Result => _working;

    private ConnectionProtocol SelectedProtocol =>
        RdpRadio.IsChecked == true ? ConnectionProtocol.Rdp :
        ConsoleRadio.IsChecked == true ? ConnectionProtocol.Console :
        WebRadio.IsChecked == true ? ConnectionProtocol.Web : ConnectionProtocol.Ssh;

    private void Protocol_Changed(object sender, RoutedEventArgs e)
    {
        if (!IsInitialized || PortBox is null || _loading) return;
        // Swap the port only while it is still one of the defaults.
        var port = PortBox.Text.Trim();
        var defaults = Enum.GetValues<ConnectionProtocol>().Select(p => Connection.DefaultPortFor(p).ToString());
        if (port.Length == 0 || defaults.Contains(port)) PortBox.Text = Connection.DefaultPortFor(SelectedProtocol).ToString();
        ApplyProtocol();
    }

    /// <summary>Remote Desktop, server consoles and web apps have no key files, tunnels or proxy: hide them.</summary>
    private void ApplyProtocol()
    {
        var protocol = SelectedProtocol;
        var ssh = protocol == ConnectionProtocol.Ssh ? Visibility.Visible : Visibility.Collapsed;
        KeyLabel.Visibility = KeyGrid.Visibility = PassphraseLabel.Visibility = PassphraseBox.Visibility = AdvancedExpander.Visibility = ssh;
        if (protocol == ConnectionProtocol.Ssh && StoredKeyPanel is not null) UpdateKeyUi();
        UserHint.Text = protocol switch
        {
            ConnectionProtocol.Rdp => "DOMAIN\\user or user@domain.com\nEntra ID accounts: AzureAD\\user@domain.com",
            ConnectionProtocol.Console => "The iLO or iDRAC login, e.g. Administrator or root. You can paste the address from your browser into Host.",
            ConnectionProtocol.Web => "The web app's login, e.g. administrator@vsphere.local, root, or root@pam for Proxmox (port 8006). You can paste the address from your browser into Host.",
            _ => "",
        };
        UserHint.Visibility = UserHint.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowPassword_Changed(object sender, RoutedEventArgs e)
    {
        if (ShowPassword.IsChecked == true)
        {
            PasswordText.Text = PasswordBox.Password;
            PasswordText.Visibility = Visibility.Visible;
            PasswordBox.Visibility = Visibility.Collapsed;
        }
        else
        {
            PasswordBox.Password = PasswordText.Text;
            PasswordBox.Visibility = Visibility.Visible;
            PasswordText.Visibility = Visibility.Collapsed;
        }
    }

    private string CurrentPassword => ShowPassword.IsChecked == true ? PasswordText.Text : PasswordBox.Password;

    private void BrowseKey_Click(object sender, RoutedEventArgs e)
    {
        var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
        var dlg = new OpenFileDialog
        {
            Title = "Select private key",
            Filter = "All files (*.*)|*.*|PuTTY keys (*.ppk)|*.ppk|PEM files (*.pem)|*.pem",
            InitialDirectory = Directory.Exists(sshDir) ? sshDir : null,
            CheckFileExists = true,
        };
        if (dlg.ShowDialog(this) == true) KeyPathBox.Text = dlg.FileName;
    }

    private void PasteKey_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new PasteKeyDialog { Owner = this };
        if (dlg.ShowDialog() != true) return;
        _storedKey = dlg.PrivateKey;
        _storedPublicKey = dlg.PublicKey;
        PassphraseBox.Password = dlg.Passphrase;
        KeyPathBox.Text = "";
        UpdateKeyUi();
    }

    private void RemoveStoredKey_Click(object sender, RoutedEventArgs e)
    {
        _storedKey = null;
        _storedPublicKey = null;
        PassphraseBox.Password = "";
        UpdateKeyUi();
    }

    private void CopyPublicKey_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_storedPublicKey)) Services.ClipboardHelper.SetText(_storedPublicKey);
    }

    private void UpdateKeyUi()
    {
        bool stored = !string.IsNullOrEmpty(_storedKey);
        StoredKeyPanel.Visibility = stored ? Visibility.Visible : Visibility.Collapsed;
        KeyPathBox.Visibility = BrowseKeyButton.Visibility = PasteKeyButton.Visibility = NewKeyButton.Visibility =
            stored ? Visibility.Hidden : Visibility.Visible;
        if (stored)
        {
            var fingerprint = string.IsNullOrEmpty(_storedPublicKey) ? "" : SshKeys.Fingerprint(_storedPublicKey);
            StoredKeyText.Text = "Kept in SimpleSSH" + (fingerprint.Length > 0 ? " · " + fingerprint.Split(' ')[0] : "");
            StoredKeyText.ToolTip = fingerprint + "\n" + (_storedPublicKey ?? "") + "\nEncrypted with your Windows account" +
                                    (Services.AppServices.Connections.Vault is null ? "." : " and your security key.");
        }
    }

    private void ExistingTags_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ExistingTags.SelectedIndex <= 0) return;
        var tag = (string)ExistingTags.SelectedItem;
        var tags = Connection.ParseTags(TagsBox.Text);
        if (!tags.Contains(tag, StringComparer.OrdinalIgnoreCase)) tags.Add(tag);
        TagsBox.Text = Connection.FormatTags(tags);
        ExistingTags.SelectedIndex = 0;
    }

    private void NewKey_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = "";
        if (!TryReadEndpoint(out var host, out var user, out var port)) return;
        if (string.IsNullOrWhiteSpace(user))
        {
            Fail("Enter the username first: the key goes into that account.", UserBox);
            return;
        }
        var proxyText = ProxyBox.Text.Trim();
        ProxySettings? proxy = null;
        if (proxyText.Length > 0 && !ProxySettings.TryParse(proxyText, out proxy, out var proxyError))
        {
            AdvancedExpander.IsExpanded = true;
            Fail(proxyError, ProxyBox);
            return;
        }

        var name = string.IsNullOrWhiteSpace(NameBox.Text) ? host : NameBox.Text.Trim();
        var dlg = new AddKeyByHandDialog(name, host, port, user, proxy, null, null, null, "Test and use") { Owner = this };
        if (dlg.ShowDialog() != true) return;
        _storedKey = dlg.PrivateKey;
        _storedPublicKey = dlg.PublicKey;
        PassphraseBox.Password = "";
        KeyPathBox.Text = "";
        UpdateKeyUi();
        if (!dlg.Tested) ErrorText.Text = "Key kept without a test.";
    }

    /// <summary>Reads host, username and port, accepting user@host:port and [IPv6]:port in the host box.</summary>
    private bool TryReadEndpoint(out string host, out string user, out int port)
    {
        // Convenience: accept an address copied from the browser, e.g. https://ilo-01.example.com/html/login.html
        var typed = HostBox.Text.Trim();
        if (typed.Contains("://") && Uri.TryCreate(typed, UriKind.Absolute, out var url) && url.IdnHost.Length > 0)
        {
            if (!url.IsDefaultPort) PortBox.Text = url.Port.ToString();
            else if (url.Scheme == Uri.UriSchemeHttps && SelectedProtocol is ConnectionProtocol.Console or ConnectionProtocol.Web) PortBox.Text = "443";
            if (url.UserInfo.Length > 0 && UserBox.Text.Trim().Length == 0) UserBox.Text = Uri.UnescapeDataString(url.UserInfo.Split(':')[0]);
            HostBox.Text = url.IdnHost;
        }

        var (h, u, portText, problem, _) = ReadHostBox();
        host = h;
        user = u;
        port = 0;
        if (problem is not null)
        {
            ShowHostCheck(force: true); // says what's wrong right under the box
            HostBox.Focus();
            return false;
        }
        if (!int.TryParse(portText, out port) || port is < 1 or > 65535)
        {
            Fail("Port must be a number between 1 and 65535.", PortBox);
            return false;
        }
        return true;
    }

    /// <summary>
    /// Splits the host box into host, username and port, and checks the host.
    /// <c>Fix</c> is the corrected host when something is wrong and there is an obvious fix.
    /// </summary>
    private (string Host, string User, string PortText, string? Problem, string? Fix) ReadHostBox()
    {
        var host = HostBox.Text.Trim();
        var user = UserBox.Text.Trim();
        var portText = PortBox.Text.Trim();

        // Convenience: accept "user@host:port" in the host field.
        var at = host.LastIndexOf('@');
        if (at > 0)
        {
            if (string.IsNullOrEmpty(user)) user = host[..at];
            host = host[(at + 1)..];
        }
        // "ilo-01.example.com/" or "ilo-01.example.com:8443/html/login.html": the host and port come before the slash.
        var path = "";
        if (host.IndexOfAny(['/', '\\']) is var slash and >= 0)
        {
            path = host[slash..];
            host = host[..slash];
        }
        if (host.StartsWith('['))
        {
            // [IPv6]:port
            var end = host.IndexOf(']');
            if (end > 0)
            {
                var rest = host[(end + 1)..];
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var v6Port)) portText = v6Port.ToString();
                host = host[1..end];
            }
        }
        else
        {
            // host:port (a single colon; bare IPv6 addresses have several)
            var colon = host.LastIndexOf(':');
            if (colon > 0 && host.IndexOf(':') == colon && int.TryParse(host[(colon + 1)..], out var embeddedPort))
            {
                portText = embeddedPort.ToString();
                host = host[..colon];
            }
        }

        var problem = HostCheck.Problem(host, out var fix);
        if (path.Length > 0 && host.Length > 0)
        {
            fix = problem is null ? host : fix;
            problem = $"Host can't contain \"{path[0]}\".";
        }
        else if (path.Length > 0)
        {
            problem = HostCheck.Problem(path, out fix);
        }
        return (host, user, portText, problem, fix);
    }

    private string? _hostFix;
    private string _hostFixUser = "", _hostFixPort = "";

    /// <summary>Shows what is wrong with the host under the box, with a one-click fix. Empty is only flagged on Save.</summary>
    private void ShowHostCheck(bool force)
    {
        var (_, user, portText, problem, fix) = ReadHostBox();
        if (problem is null || (!force && HostBox.Text.Trim().Length == 0))
        {
            HostHint.Visibility = Visibility.Collapsed;
            _hostFix = null;
            return;
        }
        HostHintText.Text = problem + (fix is null ? "" : " ");
        HostFixText.Text = fix is null ? "" : $"Use {fix}";
        HostFixLink.IsEnabled = fix is not null;
        (_hostFix, _hostFixUser, _hostFixPort) = (fix, user, portText);
        HostHint.Visibility = Visibility.Visible;
    }

    private void HostBox_LostFocus(object sender, RoutedEventArgs e) => ShowHostCheck(force: false);

    private void HostBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        // Once a problem is shown, keep it up to date as the host is corrected; don't flag half-typed hosts.
        if (HostHint.Visibility == Visibility.Visible) ShowHostCheck(force: false);
    }

    private void HostFix_Click(object sender, RoutedEventArgs e)
    {
        if (_hostFix is null) return;
        if (UserBox.Text.Trim().Length == 0) UserBox.Text = _hostFixUser;
        PortBox.Text = _hostFixPort;
        HostBox.Text = _hostFix;
        ErrorText.Text = "";
        HostHint.Visibility = Visibility.Collapsed;
        HostBox.Focus();
        HostBox.CaretIndex = HostBox.Text.Length;
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = "";
        if (!TryReadEndpoint(out var host, out var user, out var port)) return;
        var protocol = SelectedProtocol;
        var rdp = protocol != ConnectionProtocol.Ssh; // Remote Desktop / console: no keys, tunnels or proxy
        var stored = !rdp && !string.IsNullOrEmpty(_storedKey);
        var keyPath = stored ? "" : KeyPathBox.Text.Trim().Trim('"');
        if (!rdp && keyPath.Length > 0 && !File.Exists(Environment.ExpandEnvironmentVariables(keyPath)))
        {
            Fail("Private key file not found.", KeyPathBox);
            return;
        }

        var tunnelLines = TunnelsBox.Text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        if (rdp) tunnelLines.Clear(); // SSH-only settings
        if (!TunnelSpec.TryParseAll(tunnelLines, out _, out var tunnelError))
        {
            AdvancedExpander.IsExpanded = true;
            Fail("Tunnel " + tunnelError, TunnelsBox);
            return;
        }
        var proxy = ProxyBox.Text.Trim();
        if (rdp) proxy = "";
        if (proxy.Length > 0 && !ProxySettings.TryParse(proxy, out _, out var proxyError))
        {
            AdvancedExpander.IsExpanded = true;
            Fail(proxyError, ProxyBox);
            return;
        }

        _working.Protocol = protocol;
        _working.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? host : NameBox.Text.Trim();
        _working.Tunnels = tunnelLines.Count > 0 ? tunnelLines : null;
        _working.Proxy = proxy.Length > 0 ? proxy : null;
        _working.Host = host;
        _working.Port = port;
        _working.Username = user;
        _working.Password = string.IsNullOrEmpty(CurrentPassword) ? null : CurrentPassword;
        _working.PrivateKeyPath = rdp || keyPath.Length == 0 ? null : keyPath;
        _working.PrivateKey = stored ? _storedKey : null;
        _working.PublicKey = stored ? _storedPublicKey : null;
        _working.PrivateKeyPassphrase = rdp || string.IsNullOrEmpty(PassphraseBox.Password) ? null : PassphraseBox.Password;
        _working.Tags = Connection.ParseTags(TagsBox.Text);
        _working.Notes = string.IsNullOrWhiteSpace(NotesBox.Text) ? null : NotesBox.Text.Trim();
        // Only "off" is written to the file; on is the default.
        _working.CopyOnSelect = CopyOnSelectBox.IsChecked == true ? null : false;

        DialogResult = true;
    }

    private void Fail(string message, Control focus)
    {
        ErrorText.Text = message;
        focus.Focus();
        if (focus is TextBox tb) tb.SelectAll();
    }
}
