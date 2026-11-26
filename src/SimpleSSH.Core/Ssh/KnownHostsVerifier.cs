namespace SimpleSSH.Core.Ssh;

public enum HostKeyDecision
{
    Reject,
    AcceptOnce,
    AcceptAndSave,
}

/// <summary>
/// Trust-on-first-use verification backed by <see cref="KnownHostsStore"/>. Unknown or changed keys are
/// passed to <paramref name="ask"/> (typically a UI dialog) to decide.
/// </summary>
public sealed class KnownHostsVerifier : IHostKeyVerifier
{
    private readonly KnownHostsStore _store;
    private readonly Func<HostKeyInfo, HostKeyCheck, HostKeyDecision> _ask;

    public KnownHostsVerifier(KnownHostsStore store, Func<HostKeyInfo, HostKeyCheck, HostKeyDecision> ask)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _ask = ask ?? throw new ArgumentNullException(nameof(ask));
    }

    public IReadOnlyCollection<string> KnownKeyTypes(string host, int port) => _store.KnownKeyTypes(host, port);

    public bool Verify(HostKeyInfo hostKey)
    {
        var check = _store.Check(hostKey.Host, hostKey.Port, hostKey.KeyType, hostKey.FingerprintSha256);
        if (check.Status == HostKeyStatus.Trusted) return true;

        switch (_ask(hostKey, check))
        {
            case HostKeyDecision.AcceptAndSave:
                _store.Trust(hostKey.Host, hostKey.Port, hostKey.KeyType, hostKey.FingerprintSha256);
                return true;
            case HostKeyDecision.AcceptOnce:
                return true;
            default:
                return false;
        }
    }
}
