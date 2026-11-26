# SimpleSSH

A Windows SSH, Remote Desktop, server console (iLO, iDRAC) and web app (vSphere, Proxmox) client with a tagged connection list and tabbed sessions.

![SimpleSSH switching between an SSH terminal, a Remote Desktop session, an iLO console, vSphere and Proxmox tabs](docs/demo.gif)

*The app window is real; the connections are demo data and the remote screens are illustrations.*

- **Connection tree**: one flat list of connections grouped by **tag** (Firewalls, Servers, Switches, …). Tags are sorted A–Z and connections are sorted "naturally" inside each tag (`sw-2` comes before `sw-10`). A connection with several tags shows up under each one. Untagged connections go in a final **Untagged** group. A filter box searches name, host, user, tag and notes.
- **Tabs**: double-click a connection (or select it and press Enter) to open it in a new tab. Each tab is a full xterm-256color terminal with colors, Unicode, mouse selection and resize. You can have as many tabs as you like, including several to the same host. When you end a session normally (`exit`, `logout`), its tab closes automatically. If the connection drops or fails, the tab stays open so you can read the error and press Enter to reconnect. Turn this off with *View → Close tab when session exits*.
- **Add / edit / remove** connections from the toolbar, the right-click menu or the Connection menu (F2 = edit, Del = remove).
- **Drag between tags**: drag a connection onto another tag (or onto any connection in it) to move it there; hold **Ctrl** to add the tag and keep the old one, or drop on *Untagged* to clear its tags. You're asked to confirm, with a *Don't ask again* box; turn the question back on under *View → Confirm before moving between tags*.
- **Encrypted passwords**: saved passwords and key passphrases are encrypted with your Windows account (DPAPI), so nothing extra needs typing or remembering. Optionally, lock them with a **FIDO2 security key** too. See [Password security](#password-security).
- **Host keys**: trust-on-first-use. You are asked on the first connection, and you get a loud warning if a host's key changes later, or if it suddenly presents a different kind of key than the one you trusted. Trusted keys are kept in `known_hosts.json`.
- **Auth**: password, keyboard-interactive (common on switches and firewalls), and private keys (OpenSSH, PEM or PuTTY .ppk, optionally with a passphrase). Leave the password empty to be asked at connect time. Tick *Remember* in that prompt to save it (encrypted) after a successful login.
- **Switch to key login** and back: right-click a Linux server and choose *Switch to key login…*. SimpleSSH makes a key for it, adds it using your password, logs in with the key alone to prove it works, and can then turn off SSH password logins on the server. *Switch to password login…* reverses it, proving the password before letting go of the key. See [Key login](#key-login).
- **Multi-factor login**: if the server asks for more than the password, for example `Verification code:` or a Duo/RSA passcode, a small prompt shows the server's question. Codes are never saved. Logins that need a key *and* a code work too.
- **Files**: right-click a connection and choose *Open files* to get a file browser tab (SFTP). Drag files or folders in to upload; *Download* (downloaded files are marked as coming from another computer, as a browser download is, so Windows warns before running them and Office opens them in Protected View), *New folder*, *Rename* (F2), *Delete* (Del); double-click a folder to open it; to go back up, double-click *..* at the top of the list, press Backspace or Alt+Up, or use the mouse's back button. Opened from a terminal tab (right-click the tab → *Open files in …*), it starts in the folder the shell is in. SimpleSSH reads it from the prompt (the window title Ubuntu, Debian, Fedora and RHEL set by default, or OSC 7); when the prompt doesn't report it, it asks a Linux server over the same connection, without typing anything into your terminal. Devices without SFTP (many switches) get a simple SCP panel instead: type a path, then *Send file…* or *Fetch file…*.
- **Run command**: right-click a connection, or a tag to target every connection in it, and choose *Run command…*. Type e.g. `show version` and every device runs it on its own connection, up to 8 at a time. Each device's output appears in its own card, and *Copy all output* puts everything on the clipboard. Nothing is typed into your open terminals.
- **Tunnels (port forwarding)** and a **proxy**, under *Advanced* in the connection dialog (see [Tunnels and proxy](#tunnels-and-proxy)).
- **Remote Desktop (RDP)**: pick *Remote Desktop* as the connection type and it opens in a tab next to your SSH sessions, signed in with the saved (encrypted) password. See [Remote Desktop](#remote-desktop).
- **Server consoles (HPE iLO, Dell iDRAC)**: pick *Server console* as the connection type and double-click it to land straight in the server's remote console, already logged in. No web page, no *Launch console* link. See [Server consoles](#server-consoles-ilo-idrac).
- **Web apps (vSphere, ESXi, Proxmox)**: pick *Web app* as the connection type and double-click it to open the web app in a tab, already logged in. See [Web apps](#web-apps-vsphere-esxi-proxmox).
- **MSI installer**: per-machine install into Program Files with a Start Menu shortcut and an Add/Remove Programs entry. It supports clean upgrades and uninstall.
- **Free and open source**: MIT License. See [License](#license).

## Install

Download `SimpleSSH-<version>-x64.msi` from the [latest release](https://github.com/egrisdev/SimpleSSH/releases/latest) and run it. The installer is not code-signed, so Windows SmartScreen may warn before it runs. The app is self-contained, so no .NET install is needed. It requires the Microsoft Edge **WebView2 Runtime**, which ships with Windows 11 and current Windows 10. If it is missing, the app tells you where to get it.

Uninstall from *Settings → Apps* (or `msiexec /x SimpleSSH-<version>-x64.msi`). Uninstalling removes the program but **keeps your connections** in `%APPDATA%\SimpleSSH`. Delete that folder by hand if you want them gone.

Silent install for deployment: `msiexec /i SimpleSSH-1.4.6-x64.msi /qn`

## Data files

All files are under `%APPDATA%\SimpleSSH\` (override with the `SIMPLESSH_DATA_DIR` environment variable; a folder chosen that way is limited to your Windows account, like `%APPDATA%`):

| File | Contents |
|---|---|
| `connections.json` | Your connections. Passwords and passphrases in it are **encrypted** (`"dpapi:…"`) |
| `known_hosts.json` | Trusted server host-key fingerprints (SHA256) |
| `settings.json` | Window size and position, sidebar width, font size, collapsed tags |

`connections.json` is meant to be hand-editable. After editing it, use *File → Reload connections from disk*.

```json
{
  "version": 1,
  "connections": [
    {
      "id": "0818b10f-0bcc-486c-b15e-aed75f0b7790",
      "name": "core-sw-01",
      "host": "10.0.0.1",
      "port": 22,
      "username": "admin",
      "password": "dpapi:AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA…",
      "privateKeyPath": "C:\\Users\\me\\.ssh\\id_ed25519",
      "privateKeyPassphrase": null,
      "tags": [ "Switches", "Core" ],
      "notes": "Rack A3"
    }
  ]
}
```

You can still type a plain password into the file by hand (`"password": "hunter2"`). SimpleSSH encrypts it the next time it loads the file.

Only `host` is required. `id` is generated if missing, `port` defaults to 22, and `name` defaults to the host.

Logs (errors only) go to `%LOCALAPPDATA%\SimpleSSH\logs\simplessh.log`.

## Tunnels and proxy

Both live under *Advanced* in the connection dialog, which stays collapsed unless a connection uses them.

**Tunnels**: one per line, written the OpenSSH way. They open with the terminal tab and close with it. The terminal shows one line per tunnel saying whether it opened.

| Line | Meaning |
|---|---|
| `L 8080:db:5432` | `localhost:8080` on this PC reaches `db:5432` through the server (like `ssh -L`) |
| `L 0.0.0.0:8080:db:5432` | Same, but other PCs can use your port 8080 too |
| `R 9000:localhost:22` | Port 9000 *on the server* reaches `localhost:22` on this PC (like `ssh -R`) |
| `D 1080` | A SOCKS proxy on `localhost:1080` that browses from the server's side (like `ssh -D`) |

**Proxy**: reach the server through a proxy, written as a URL: `socks5://host:1080`, `socks4://host:1080` or `http://proxy:3128` (HTTP CONNECT). Credentials go in the URL (`socks5://user:password@host:1080`). A proxy URL that contains a password is encrypted on disk like other passwords.

## Key login

**Switch to key login** (right-click an SSH connection) moves a Linux or Unix server from password to key login in one go:

1. **Create a key**: a new Ed25519 key for this server. It is kept inside SimpleSSH, encrypted like your passwords (Windows account, plus your security key if that's on). No key file is written.
2. **Add it to the server**: logs in the way that works today and appends the public key to `~/.ssh/authorized_keys` (creating the folder and fixing permissions; adding it twice does nothing).
3. **Log in with the key alone**: a fresh login with no password and no prompts. Only when this works is the key saved on the connection. You can then let SimpleSSH forget the saved password.

**Lock down (optional)**: *Turn off password logins* adds one file, `/etc/ssh/sshd_config.d/00-simplessh-keys-only.conf` (`PubkeyAuthentication yes`, `PasswordAuthentication no` and `KbdInteractiveAuthentication no`, nothing else, so your other SSH settings stay as they are), checks it with `sshd -t`, and restarts ssh. It needs sudo (the login password is used, or you're asked). To make sure you can't be locked out, it keeps a key login open while it does this, then opens a *new* key login; if that fails it undoes the change over the open session. Finally it checks that a password login is now refused. Console logins are not affected. *Turn password logins back on* in the same window removes the file, or on the server run:

```bash
sudo rm /etc/ssh/sshd_config.d/00-simplessh-keys-only.conf && sudo systemctl restart ssh
```

Made for OpenSSH with a drop-in folder (`/etc/ssh/sshd_config.d`, included from `sshd_config`): Ubuntu 20.04 and later, Debian 11 and later, and most current distributions. Servers without it are left unchanged, with a message.

**Switching back** to password login is just as safe: right-click the connection → *Switch to password login…*, type the password and choose *Switch*. SimpleSSH logs in with the key and turns SSH password logins back on (only if its lock-down file is there; sudo is asked for only then), logs in with the password alone to prove it, and only then removes the key from SimpleSSH and, unless you untick it, from the server's `authorized_keys`. If the key no longer gets in, that first step is skipped and the password simply has to work. For a connection that uses a key, the menu shows *Lock down (key login)…* and *Switch to password login…*; otherwise *Switch to key login…*.

**Server already refuses passwords?** Choose *New key…* next to *Private key* in the connection dialog (or *Add the key by hand instead* in *Switch to key login*). SimpleSSH makes a key and shows a one-line command; paste it into a session that already gets in (another SSH program, or the console), logged in as the same user, then choose *Test*. The command adds the key to `~/.ssh/authorized_keys` once and sets the permissions SSH needs; SimpleSSH keeps the key only after a key-only login works (or if you choose *Keep the key without testing*).

**Already have a key on Linux?** In the connection dialog, choose *Paste…* next to *Private key*, and paste the output of `cat ~/.ssh/id_ed25519`. SimpleSSH checks it, shows its fingerprint, and keeps it encrypted; *Copy public key* gives you the line for `authorized_keys`. Key files (*Browse…*) still work as before.

## Remote Desktop

In the connection dialog choose **Type: Remote Desktop (RDP)**. The port switches to 3389, and the SSH-only fields (key file, tunnels, proxy) are hidden. Usernames work the way Windows expects them: `DOMAIN\user`, `user@domain.com`, or `AzureAD\user@domain.com` for Entra ID accounts.

- **In a tab**: double-click the connection. SimpleSSH hosts the Remote Desktop control that is built into Windows, the same engine as the Remote Desktop app, so nothing extra is installed. Sign-in uses Network Level Authentication with the saved password, or asks for it (with *Remember*) like SSH does. The remote desktop resizes to fit the tab on Windows 8.1 / Server 2012 R2 and later; older servers are scaled to fit. Clipboard and smart cards are shared; drives and printers are not. If the server's certificate can't be verified you get the standard Windows warning.
- **Keys**: while the remote desktop has focus, keys go to the remote PC (Alt+Tab stays local unless you are in full screen). Click a tab header to switch tabs. *Tab → Full screen* or **Ctrl+Alt+Break** toggles full screen; the bar at the top of the screen brings you back.
- **Signing out** on the remote PC closes the tab (like `exit` in SSH). If the connection drops, the tab says why and offers *Connect again*.
- **Open in Remote Desktop window**: in the right-click menu (and on the tab), for when you need what the full Windows app offers, such as multiple monitors, RD Gateway or drive redirection. SimpleSSH writes a small `.rdp` file (no password in it) and hands the saved password to Windows Credential Manager for your current Windows sign-in only (cleared when you sign out). A password you saved yourself in the Remote Desktop app is never overwritten. If your organization blocks saved credentials for Remote Desktop, the app simply asks for the password.
- **Two tabs to the same PC** with the same account would take over each other's session, so RDP tabs have no *Duplicate*. *Files* and *Run command* are SSH features and aren't offered for RDP connections.

## Server consoles (iLO, iDRAC)

In the connection dialog choose **Type: Server console (iLO, iDRAC)**, and enter the controller's address (you can paste it from your browser, e.g. `https://ilo-07.example.com/`), its username and password. Double-click it and the server's screen opens in a tab, the way HPE OneView and Dell OpenManage do it: SimpleSSH logs in through the controller's management API (Redfish) and hands the console a ready session.

- **HPE iLO 4, 5 and 6**: opens iLO's own HTML5 console (`/irc.html`) with a fresh iLO session. Closing the tab ends that session, so it doesn't use up one of the iLO's session slots. iLO 4 firmware too old for the HTML5 console opens the iLO web page instead, already signed in.
- **Dell iDRAC 9**: the iDRAC hands out a one-time console login, so its virtual console opens directly. iDRACs that can't do that (iDRAC 8, old firmware) open the console page and ask you to log in once.
- **Checked before it opens**, so you get a plain answer instead of a blank page: a wrong username or password says so; an iLO with only the *Standard* licence (console limited to start-up) gets a note above the console; an iDRAC without an *Enterprise* or *Datacenter* licence (rack and tower servers need one for the console) opens its web page with an explanation. Anything else at that address (another make of controller, a plain web page) opens as a web page.
- **Certificates**: iLOs and iDRACs nearly always have self-signed certificates. The first time, SimpleSSH shows the certificate's fingerprint and asks once (*Trust and connect*); it is remembered in `known_hosts.json`, and you are warned if it ever changes.
- The console page is the controller's own, so its keyboard, power, virtual media and full-screen buttons all work. *Open in browser* (right-click menu, tab, or when something fails) opens the controller's web page in your browser instead.
- Each console tab is a private browser of its own: the session stays in memory and isn't written to disk, and the tab can't be sent to another site.
- **Opens quickly**: the console page's own files (scripts, styles, fonts) are kept in `%LOCALAPPDATA%\SimpleSSH\console-cache`, and each time SimpleSSH only asks the controller whether they changed, which takes milliseconds instead of downloading them again. Nothing with a session in it is kept, and files unused for two months are removed.
- SimpleSSH only signs in and opens the console. It never changes the controller's settings, power or media. Nothing is logged except which kind of console opened and how long it took.

## Web apps (vSphere, ESXi, Proxmox)

In the connection dialog choose **Type: Web app (vSphere, ESXi, Proxmox)**, and enter the address (you can paste it from your browser, e.g. `https://pve-01.example.com:8006/`), the username and password. Double-click it and the web app opens in a tab, already logged in.

- **Proxmox VE and Proxmox Backup Server**: SimpleSSH logs in through Proxmox's API and hands the page the same login ticket its own login screen gets. Proxmox listens on port **8006** (Backup Server: 8007). User names name their realm, e.g. `root@pam` or `admin@pve`; without one, `@pam` is used, as on Proxmox's login screen. An account with two-factor login opens the login screen for you to finish.
- **vCenter (vSphere Client) and ESXi (Host Client)**: opens the client at `/ui/` and fills in its login form, then sends it, the way you would. Use the full user name for vCenter, e.g. `administrator@vsphere.local`.
- **Any other web app with a login page** (NAS, firewall, switch…): its login form is filled in and sent the same way.
- **One try**: the login is filled in once per connect. If it's refused, the page shows its own message and you can type there; SimpleSSH doesn't send the password again (that could lock the account). *Reconnect* tries once more.
- The password is only ever filled in on pages at exactly the connection's address, and only sent to Proxmox's own API at that address. Certificates, private browser tabs and *Open in browser* work as for [server consoles](#server-consoles-ilo-idrac).

## Password security

Saved passwords and key passphrases are encrypted with **Windows DPAPI** (current-user scope), the same mechanism Windows uses for saved RDP and Wi-Fi credentials. The key comes from your Windows sign-in, so there is no master password and no extra prompt. You sign in to Windows as usual and SimpleSSH can read your passwords. It works the same for local, Active Directory, hybrid (AAD-joined with AD users) and Entra ID (AAD) accounts, including Windows Hello and PIN sign-in.

**What it protects against:** someone who gets the `connections.json` file (a copied profile, a backup, a file share, an email attachment, a removed disk) or another user on the same PC. Without your Windows account, they only see `dpapi:…` blobs.

**What it doesn't protect against:** malware or anyone running programs *as you* while you are signed in. That is true of every password store that doesn't make you type a password, including browsers and Credential Manager.

**Practical notes:**
- **Existing plain-text passwords** are encrypted automatically the first time this version starts.
- **Roaming profiles** (AD): the DPAPI keys roam with your profile, so passwords work on every PC you sign in to.
- **Changing your Windows password** normally is fine. After an admin reset, AD accounts recover through the domain controller's DPAPI backup key. For local and Entra ID-only accounts, a forced reset can make saved passwords unreadable.
- **Unreadable passwords** happen when the file was copied from another user or the keys were lost. Nothing breaks: the status bar says how many there are, and SimpleSSH asks for the password once when you connect. *Remember* is pre-ticked so it is re-saved. The old value is never deleted until you replace it.

### Security key (optional)

**File → Security key… → Turn on** adds a second lock: saved passwords then also need your FIDO2 security key (YubiKey 5, Feitian, Google Titan, SoloKey and most other FIDO2 keys). When SimpleSSH starts, the Windows Security prompt asks you to touch the key and enter its PIN; that's it until you close the app.

- **How it works:** a random 256-bit data key encrypts every password (AES-256-GCM). The data key is stored only encrypted: with a secret that only your physical key can produce (the FIDO2 *hmac-secret* feature, PIN required), wrapped again with your Windows account (DPAPI), and separately with your recovery key. While locked, no password is in memory.
- **Recovery key:** setup shows a recovery key once, with a *Copy* button (kept out of Windows clipboard history and cleared after 2 minutes). Store it in your password manager. If the security key is lost or broken, the recovery key unlocks your passwords on any PC; you can then set up a new key. You can make a new recovery key at any time: SimpleSSH then locks your passwords again with a new key (touch each security key once), so the old recovery key no longer opens them, not even in an older copy or backup of the file. If a security key is lost or stolen, remove it and then make a new recovery key.
- **More than one key:** *Add another key…* registers a spare; each key unlocks on its own.
- **New passwords:** saving a new password (a new connection, an edit, *Remember* at login, a new SSH key) asks you to unlock first if SimpleSSH is locked, so the security key protects it too, never just Windows.
- **When to lock:** *When SimpleSSH closes* (default), or *When SimpleSSH closes or Windows locks*. Open sessions stay connected; the key is needed again for the next saved password. You can also lock right away from the status bar or **File → Lock saved passwords**.
- **What it adds:** someone using your Windows account (malware while SimpleSSH is closed, a borrowed PC, a domain admin with the DPAPI backup key) can't read your passwords without the key and its PIN. It can't protect against malware running while SimpleSSH is unlocked, which nothing can.
- **Other PCs:** the key works where your Windows account (DPAPI) does. On a new PC or account, unlock with the recovery key once and SimpleSSH offers to set the key up there.
- **Remote Desktop:** security keys can't reach apps through Remote Desktop from a Mac, iPad or Android (Microsoft's Windows App doesn't pass them on), so over Remote Desktop SimpleSSH asks for the recovery key instead. *Try my security key anyway* is one click away.
- **Turning it off** (needs one unlock) goes back to Windows-account encryption.
- Requires Windows 11 or an up-to-date Windows 10. Windows Hello is not used.

## Keyboard shortcuts

| Where | Keys | Action |
|---|---|---|
| List | Double-click / Enter | Open in new tab |
| List | F2 / Del | Edit / remove |
| Anywhere | Ctrl+Shift+N | New connection |
| Anywhere | Ctrl+Shift+F | Filter connections |
| Anywhere | Ctrl+Tab / Ctrl+Shift+Tab (or Ctrl+PgDn / PgUp) | Next / previous tab |
| Anywhere | Ctrl+Shift+W, middle-click a tab | Close tab |
| Anywhere | Ctrl+Shift+R | Reconnect current tab |
| Anywhere | Drag a tab left or right | Move it |
| Terminal | Select text (drag, double-click a word, triple-click a line) | Copy, right away. Turn it off per connection in *Edit → Advanced → Terminal*; then copy with Ctrl+C / Ctrl+Shift+C / right-click |
| Terminal | Ctrl+C / Ctrl+Shift+C with text selected | Copy (Ctrl+C with nothing selected still sends ^C) |
| Terminal | Ctrl+V / Ctrl+Shift+V / Shift+Ins / right-click | Paste |
| Terminal | Ctrl + = / - / 0, Ctrl+wheel | Font size |
| Terminal | Enter after a disconnect | Reconnect |
| Files tab | Enter / double-click | Open folder, or download a file |
| Files tab | Backspace / Alt+Up / mouse back button / double-click *..* | Parent folder |
| Files tab | F2 / Del / F5 | Rename / delete / refresh |
| Files tab | Drag files from Explorer | Upload into the current folder |
| Remote Desktop tab | Ctrl+Alt+Break | Full screen on / off |

Shortcuts the shell needs (Ctrl+W, Ctrl+N, Ctrl+R, Ctrl+F, …) are left alone and go to the terminal.

Command line: `SimpleSSH.exe --connect "core-sw-01"` opens a saved connection (by name, host or id) at startup; repeat it to open several. `--files "core-sw-01"` opens a Files tab, and `--run "Switches"` opens Run command for a connection or for every connection in a tag.

## Building

Requirements: the .NET 8 SDK. Node.js is needed only to run the integration tests. WiX is pulled in automatically from NuGet as an MSBuild SDK.

```powershell
./build.ps1                    # tests + self-contained publish + MSI  -> artifacts\installer\SimpleSSH-1.4.6-x64.msi
./build.ps1 -Version 1.5.0     # bump the version (needed for an MSI upgrade to replace the old one)
./build.ps1 -SkipTests
dotnet run --project src/SimpleSSH   # run from source
```

### Layout

```
src/SimpleSSH.Core/     UI-free logic (unit tested)
  Models/Connection.cs            the saved connection
  Storage/ConnectionStore.cs      JSON load/save (atomic writes, encrypted secrets)
  Credentials/SecretProtector.cs   DPAPI encryption of passwords at rest
  Credentials/SecurityKeyVault.cs  optional security-key layer: data key, key slots, recovery key
  TagGrouping.cs                  builds the tag -> connections tree + filter
  Credentials/ICredentialProvider.cs   <- seam for secure credential storage
  Ssh/SshConnector.cs             one way to connect: auth (incl. MFA prompts), proxy, host keys
  Ssh/SshTerminalSession.cs       interactive shell (PTY, resize, UTF-8 decoding) + tunnels
  Ssh/FileTransfer.cs             SFTP browsing/transfer, SCP fallback
  Ssh/SshCommandRunner.cs         "Run command" (exec channel)
  Ssh/SshKeys.cs, KeyLoginSetup.cs  key generation; Switch to key login + lock down (with automatic undo)
  Ssh/TunnelSpec.cs, ProxySettings.cs   parsing of the Advanced settings
  Ssh/KnownHostsStore.cs/Verifier TOFU host-key checking
  Rdp/RdpSettings.cs              RDP helpers: usernames, .rdp file, scaling
  Bmc/ServerConsole.cs            iLO / iDRAC: detect, log in (Redfish), decide console or web page
  Bmc/WebApps.cs                  web apps: detect Proxmox / vSphere / ESXi, Proxmox ticket login, login-form fill script
src/SimpleSSH/          WPF app
  MainWindow.xaml                 tree + tab strip
  Controls/TerminalView.xaml      terminal tab: WebView2 hosting xterm.js <-> SshTerminalSession
  Controls/FilesView.xaml         files tab (SFTP / SCP)
  Controls/RdpView.xaml           Remote Desktop tab (Windows RDP ActiveX control, RdpClientHost.cs)
  Controls/ConsoleView.xaml       server console and web app tab (WebView2: iLO / iDRAC HTML5 console, or the web app)
  Services/RdpLauncher.cs         "Open in Remote Desktop window" (mstsc + session-only credential)
  Views/RunCommandWindow.xaml     run one command on many connections
  Services/SessionLogin.cs        shared login flow (prompts, remember, host-key retry)
  Services/WebAuthn.cs            FIDO2 security keys via Windows webauthn.dll (hmac-secret)
  Views/SecurityKeyDialog.xaml    turn the security key on/off, keys, recovery key, lock options
  wwwroot/                        terminal page (xterm.js 5.5 vendored, no CDN)
installer/              WiX v5 MSI (Package.wxs)
tests/SimpleSSH.Tests/  xUnit: storage, grouping, known hosts, and live SSH tests
tools/testserver/       Node ssh2 test server (shell, exec, SFTP, SCP, forwarding, MFA users) + proxy.js (SOCKS4/5, HTTP)
```

### Pulling passwords from a vault or API later

Encryption at rest lives in `Credentials/SecretProtector.cs` (`ISecretProtector`, used by `ConnectionStore`). Every SSH connection gets its credentials through `ICredentialProvider.ResolveAsync(connection)`. Today that is `StoredCredentialProvider`, which returns the decrypted saved fields. To pull secrets from a vault or API:

1. Implement `ICredentialProvider`. For example, look up the secret by `connection.Id` or `connection.Host`, then return a `ResolvedCredential`.
2. Swap it in at `AppServices.Credentials` (`src/SimpleSSH/Services/AppServices.cs`).
3. Stop writing `password` / `privateKeyPassphrase` to the JSON, and strip them from existing files.

The UI and SSH layers don't need to change.

### Tests

`dotnet test` runs unit tests plus integration tests that start `tools/testserver/server.js` on a free port. Run `npm install` in `tools/testserver` once first. The integration tests cover password login, the interactive shell, PTY resize, UTF-8 and emoji output, large output, wrong passwords, rejected and trusted host keys, refused connections, clean disposal, multi-factor login, Run command, SFTP browse/upload/download/rename/delete/cancel, SCP, local/remote/SOCKS tunnels and SOCKS4/SOCKS5/HTTP proxies.

To try the app by hand against the test server: `node tools/testserver/server.js 2222`, then add a connection to `127.0.0.1`, port 2222, user `test`, password `test`.

## Disclaimer

SimpleSSH is a free, unofficial, community tool. It is provided **"as is", without warranty of any kind**, and the authors accept **no liability** for any damage, data loss, security incident or other harm that comes from using it (see the [license](LICENSE)). It can run commands on and copy files to many devices at once, so check what you run. Review the code and test it before relying on it in production, and follow your organization's security policies.

Product names mentioned here (Windows, Cisco, Duo, RSA and so on) are trademarks of their owners and are used only to describe compatibility. SimpleSSH is not affiliated with or endorsed by any of them.

## License

SimpleSSH is released under the [MIT License](LICENSE): anyone may use, copy, modify and distribute it, commercially or not, for any purpose. The only condition is keeping the copyright and license notice.

Third-party components keep their own licenses (MIT and BSD-style). See [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Both files are also installed next to `SimpleSSH.exe`.
