using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SimpleSSH.Services;

public sealed class WebAuthnException : Exception
{
    public WebAuthnException(string message, bool cancelled = false) : base(message) => Cancelled = cancelled;

    /// <summary>The user closed the Windows Security prompt (or it timed out).</summary>
    public bool Cancelled { get; }
}

/// <summary>
/// FIDO2 security keys through the Windows WebAuthn API (webauthn.dll, Windows 10 1903+; hmac-secret needs a
/// newer Windows 10/11). Windows shows its own Security prompt for the touch and PIN, so no admin rights or
/// drivers are needed. The calls block until the user is done: run them off the UI thread.
/// </summary>
/// <remarks>
/// Structure layouts follow webauthn.h (github.com/microsoft/webauthn). Only the fields up to the versions we
/// ask for are declared; Windows reads and writes according to each structure's dwVersion.
/// User verification (PIN) is always required: hmac-secret gives a different secret with and without it, so a
/// key that later got a PIN would otherwise stop opening the passwords.
/// </remarks>
internal static unsafe class WebAuthn
{
    private const string Dll = "webauthn.dll";
    private const uint MinApiVersion = 4; // hmac-secret salts in GetAssertion
    private const int TimeoutMs = 120_000;
    private const uint AttachmentCrossPlatform = 2;
    private const uint UserVerificationRequired = 1;
    private const uint AttestationNone = 1;
    private const int CoseEs256 = -7;
    private const int CoseRs256 = -257;
    private const int NteUserCancelled = unchecked((int)0x80090036);

    public sealed record Registration(byte[] CredentialId);

    public sealed record Secret(byte[] CredentialId, byte[] Value);

    private static readonly object CancelGate = new();
    private static Guid? _current;

    /// <summary>
    /// Asks Windows to close the prompt of the operation in progress. Best effort: Windows reports success but can
    /// keep its device-choice screen open until the user closes it, so callers must not wait for this to take effect.
    /// </summary>
    public static void CancelCurrent()
    {
        lock (CancelGate)
        {
            if (_current is not { } id) return;
            try { WebAuthNCancelCurrentOperation(&id); }
            catch (EntryPointNotFoundException) { }
        }
    }

    private static Guid* BeginOperation(Guid* storage)
    {
        try
        {
            if (WebAuthNGetCancellationId(storage) != 0) return null;
        }
        catch (EntryPointNotFoundException)
        {
            return null;
        }
        lock (CancelGate) _current = *storage;
        return storage;
    }

    private static void EndOperation()
    {
        lock (CancelGate) _current = null;
    }

    /// <summary>True if this Windows can give an app a security key's hmac-secret.</summary>
    public static bool IsSupported(out string reason)
    {
        try
        {
            var version = WebAuthNGetApiVersionNumber();
            if (version >= MinApiVersion)
            {
                reason = "";
                return true;
            }
            reason = $"This version of Windows is too old for security key encryption (WebAuthn API {version}, needs {MinApiVersion}). Windows 11 or an updated Windows 10 is required.";
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            reason = "This version of Windows does not support security keys for apps (webauthn.dll is missing).";
        }
        return false;
    }

    /// <summary>Creates a credential with hmac-secret on a security key (touch + PIN).</summary>
    /// <param name="exclude">Already registered credentials: Windows says so instead of registering the same key twice.</param>
    public static Registration Register(IntPtr hwnd, string rpId, IReadOnlyList<byte[]> exclude)
    {
        var userId = RandomNumberGenerator.GetBytes(16);
        var clientData = ClientData("webauthn.create", rpId);
        int hmacSecret = 1; // BOOL TRUE
        using var pins = new Pins();
        var excluded = pins.Credentials(exclude);

        fixed (char* rpIdP = rpId, rpName = "SimpleSSH", userName = "SimpleSSH", userDisplay = "SimpleSSH saved passwords",
               publicKey = "public-key", sha256 = "SHA-256", hmacId = "hmac-secret")
        fixed (byte* userIdP = userId, clientDataP = clientData)
        {
            var rp = new RpEntity { Version = 1, Id = rpIdP, Name = rpName };
            var user = new UserEntity { Version = 1, IdLength = (uint)userId.Length, Id = userIdP, Name = userName, DisplayName = userDisplay };
            var algs = stackalloc CoseParameter[2];
            algs[0] = new CoseParameter { Version = 1, Type = publicKey, Alg = CoseEs256 };
            algs[1] = new CoseParameter { Version = 1, Type = publicKey, Alg = CoseRs256 };
            var parameters = new CoseParameters { Count = 2, Items = algs };
            var cd = new WebAuthnClientData { Version = 1, JsonLength = (uint)clientData.Length, Json = clientDataP, HashAlgorithm = sha256 };
            var extension = new Extension { Id = hmacId, Size = sizeof(int), Value = &hmacSecret };
            var options = new MakeCredentialOptions
            {
                Version = 3,
                TimeoutMs = TimeoutMs,
                ExcludeCredentials = excluded.WithType(publicKey),
                Extensions = new Extensions { Count = 1, Items = &extension },
                Attachment = AttachmentCrossPlatform,
                UserVerification = UserVerificationRequired,
                Attestation = AttestationNone,
            };
            Guid cancellation;
            options.CancellationId = BeginOperation(&cancellation);

            Attestation* result = null;
            int hr;
            try
            {
                hr = WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &parameters, &cd, &options, &result);
            }
            finally
            {
                EndOperation();
            }
            if (hr != 0) throw Error(hr, "register the security key");
            try
            {
                if (result->CredentialIdLength == 0) throw new WebAuthnException("The security key did not return a credential.");
                if (result->Version >= 2 && !HasHmacSecret(result->Extensions))
                    throw new WebAuthnException("This security key does not support the hmac-secret feature needed to encrypt passwords. Most FIDO2 keys (YubiKey 5, Feitian, Google Titan, SoloKey) do.");
                return new Registration(new ReadOnlySpan<byte>(result->CredentialId, (int)result->CredentialIdLength).ToArray());
            }
            finally
            {
                WebAuthNFreeCredentialAttestation(result);
            }
        }
    }

    /// <summary>Asks one of <paramref name="allow"/> for its hmac-secret over <paramref name="salt"/> (touch + PIN).</summary>
    public static Secret GetSecret(IntPtr hwnd, string rpId, IReadOnlyList<byte[]> allow, byte[] salt)
    {
        if (allow.Count == 0) throw new ArgumentException("No security keys to ask.", nameof(allow));
        var clientData = ClientData("webauthn.get", rpId);
        using var pins = new Pins();
        var allowed = pins.Credentials(allow);

        fixed (char* rpIdP = rpId, publicKey = "public-key", sha256 = "SHA-256")
        fixed (byte* clientDataP = clientData, saltP = salt)
        {
            var cd = new WebAuthnClientData { Version = 1, JsonLength = (uint)clientData.Length, Json = clientDataP, HashAlgorithm = sha256 };
            var hmacSalt = new HmacSecretSalt { FirstLength = (uint)salt.Length, First = saltP };
            var saltValues = new HmacSecretSaltValues { Global = &hmacSalt };
            var options = new GetAssertionOptions
            {
                Version = 6,
                TimeoutMs = TimeoutMs,
                AllowCredentials = allowed.WithType(publicKey),
                Attachment = AttachmentCrossPlatform,
                UserVerification = UserVerificationRequired,
                HmacSecretSaltValues = &saltValues,
            };
            Guid cancellation;
            options.CancellationId = BeginOperation(&cancellation);

            Assertion* result = null;
            int hr;
            try
            {
                hr = WebAuthNAuthenticatorGetAssertion(hwnd, rpIdP, &cd, &options, &result);
            }
            finally
            {
                EndOperation();
            }
            if (hr != 0) throw Error(hr, "use the security key");
            try
            {
                if (result->Version < 3 || result->HmacSecret is null || result->HmacSecret->FirstLength < 32)
                    throw new WebAuthnException("The security key did not return its secret (hmac-secret). Update Windows, or use a key that supports hmac-secret.");
                var credentialId = new ReadOnlySpan<byte>(result->Credential.Id, (int)result->Credential.IdLength).ToArray();
                var value = new ReadOnlySpan<byte>(result->HmacSecret->First, (int)result->HmacSecret->FirstLength).ToArray();
                return new Secret(credentialId, value);
            }
            finally
            {
                WebAuthNFreeAssertion(result);
            }
        }
    }

    private static byte[] ClientData(string type, string rpId)
    {
        // Native apps supply their own client data; Windows only hashes it into the signed request.
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return Encoding.UTF8.GetBytes($"{{\"type\":\"{type}\",\"challenge\":\"{challenge}\",\"origin\":\"{rpId}\"}}");
    }

    private static bool HasHmacSecret(Extensions extensions)
    {
        for (int i = 0; i < extensions.Count; i++)
        {
            var e = extensions.Items[i];
            if (e.Id is not null && new string(e.Id) == "hmac-secret" && e.Size >= sizeof(int) && e.Value is not null)
                return *(int*)e.Value != 0;
        }
        return false;
    }

    private static WebAuthnException Error(int hr, string action)
    {
        if (hr == NteUserCancelled) return new WebAuthnException("Cancelled.", cancelled: true);
        string name = "";
        try
        {
            var p = WebAuthNGetErrorName(hr);
            if (p != IntPtr.Zero) name = Marshal.PtrToStringUni(p) ?? "";
        }
        catch (EntryPointNotFoundException) { }
        Log.Info($"WebAuthn could not {action}: 0x{hr:X8} {name}");
        // NotAllowedError covers "closed the prompt", "timed out" and "this key is not registered".
        if (name == "NotAllowedError")
            return new WebAuthnException("The security key was not used (cancelled, timed out, or it is not a key registered here).", cancelled: true);
        if (name == "InvalidStateError")
            return new WebAuthnException("This security key is already registered.");
        return new WebAuthnException($"Could not {action}: {(name.Length > 0 ? name + " " : "")}(0x{hr:X8}).");
    }

    /// <summary>Pins credential ids for the duration of a call.</summary>
    private sealed class Pins : IDisposable
    {
        private readonly List<GCHandle> _handles = new();
        private Credential[]? _items;
        private GCHandle _itemsHandle;

        public PinnedCredentials Credentials(IReadOnlyList<byte[]> ids)
        {
            _items = new Credential[ids.Count];
            for (int i = 0; i < ids.Count; i++)
            {
                var h = GCHandle.Alloc(ids[i], GCHandleType.Pinned);
                _handles.Add(h);
                _items[i] = new Credential { Version = 1, IdLength = (uint)ids[i].Length, Id = (byte*)h.AddrOfPinnedObject() };
            }
            _itemsHandle = GCHandle.Alloc(_items, GCHandleType.Pinned);
            return new PinnedCredentials(_items, (Credential*)_itemsHandle.AddrOfPinnedObject());
        }

        public void Dispose()
        {
            if (_itemsHandle.IsAllocated) _itemsHandle.Free();
            foreach (var h in _handles) h.Free();
        }
    }

    private readonly struct PinnedCredentials
    {
        private readonly Credential[] _items;
        private readonly Credential* _pointer;

        public PinnedCredentials(Credential[] items, Credential* pointer)
        {
            _items = items;
            _pointer = pointer;
        }

        public Credentials WithType(char* type)
        {
            for (int i = 0; i < _items.Length; i++) _pointer[i].Type = type;
            return new Credentials { Count = (uint)_items.Length, Items = _items.Length == 0 ? null : _pointer };
        }
    }

    // ---- webauthn.h --------------------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct RpEntity { public uint Version; public char* Id; public char* Name; public char* Icon; }

    [StructLayout(LayoutKind.Sequential)]
    private struct UserEntity { public uint Version; public uint IdLength; public byte* Id; public char* Name; public char* Icon; public char* DisplayName; }

    [StructLayout(LayoutKind.Sequential)]
    private struct WebAuthnClientData { public uint Version; public uint JsonLength; public byte* Json; public char* HashAlgorithm; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CoseParameter { public uint Version; public char* Type; public int Alg; }

    [StructLayout(LayoutKind.Sequential)]
    private struct CoseParameters { public uint Count; public CoseParameter* Items; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credential { public uint Version; public uint IdLength; public byte* Id; public char* Type; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Credentials { public uint Count; public Credential* Items; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Extension { public char* Id; public uint Size; public void* Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Extensions { public uint Count; public Extension* Items; }

    [StructLayout(LayoutKind.Sequential)]
    private struct HmacSecretSalt { public uint FirstLength; public byte* First; public uint SecondLength; public byte* Second; }

    [StructLayout(LayoutKind.Sequential)]
    private struct HmacSecretSaltValues { public HmacSecretSalt* Global; public uint CredentialCount; public void* CredentialSalts; }

    /// <summary>WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, version 3.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MakeCredentialOptions
    {
        public uint Version;
        public uint TimeoutMs;
        public Credentials ExcludeCredentials;
        public Extensions Extensions;
        public uint Attachment;
        public int RequireResidentKey;
        public uint UserVerification;
        public uint Attestation;
        public uint Flags;
        public Guid* CancellationId;          // v2
        public void* ExcludeCredentialList;   // v3
    }

    /// <summary>WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, version 6.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct GetAssertionOptions
    {
        public uint Version;
        public uint TimeoutMs;
        public Credentials AllowCredentials;
        public Extensions Extensions;
        public uint Attachment;
        public uint UserVerification;
        public uint Flags;
        public char* U2fAppId;                       // v2
        public int* U2fAppIdUsed;
        public Guid* CancellationId;                 // v3
        public void* AllowCredentialList;            // v4
        public uint CredLargeBlobOperation;          // v5
        public uint CredLargeBlobLength;
        public byte* CredLargeBlob;
        public HmacSecretSaltValues* HmacSecretSaltValues; // v6
        public int BrowserInPrivateMode;
    }

    /// <summary>WEBAUTHN_CREDENTIAL_ATTESTATION up to version 2.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct Attestation
    {
        public uint Version;
        public char* FormatType;
        public uint AuthenticatorDataLength;
        public byte* AuthenticatorData;
        public uint AttestationLength;
        public byte* AttestationData;
        public uint AttestationDecodeType;
        public void* AttestationDecode;
        public uint AttestationObjectLength;
        public byte* AttestationObject;
        public uint CredentialIdLength;
        public byte* CredentialId;
        public Extensions Extensions;                // v2
    }

    /// <summary>WEBAUTHN_ASSERTION up to version 3.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct Assertion
    {
        public uint Version;
        public uint AuthenticatorDataLength;
        public byte* AuthenticatorData;
        public uint SignatureLength;
        public byte* Signature;
        public Credential Credential;
        public uint UserIdLength;
        public byte* UserId;
        public Extensions Extensions;                // v2
        public uint CredLargeBlobLength;
        public byte* CredLargeBlob;
        public uint CredLargeBlobStatus;
        public HmacSecretSalt* HmacSecret;           // v3
    }

    [DllImport(Dll, ExactSpelling = true)]
    private static extern uint WebAuthNGetApiVersionNumber();

    [DllImport(Dll, ExactSpelling = true)]
    private static extern int WebAuthNAuthenticatorMakeCredential(IntPtr hWnd, RpEntity* rp, UserEntity* user,
        CoseParameters* pubKeyCredParams, WebAuthnClientData* clientData, MakeCredentialOptions* options, Attestation** attestation);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern int WebAuthNAuthenticatorGetAssertion(IntPtr hWnd, char* rpId, WebAuthnClientData* clientData,
        GetAssertionOptions* options, Assertion** assertion);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern void WebAuthNFreeCredentialAttestation(Attestation* attestation);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern void WebAuthNFreeAssertion(Assertion* assertion);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern IntPtr WebAuthNGetErrorName(int hr);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern int WebAuthNGetCancellationId(Guid* cancellationId);

    [DllImport(Dll, ExactSpelling = true)]
    private static extern int WebAuthNCancelCurrentOperation(Guid* cancellationId);
}
