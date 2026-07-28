namespace FieldGuard;

/// <summary>Base type for everything this library throws on purpose.</summary>
public class FieldGuardException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public FieldGuardException(string message) : base(message) { }
    /// <summary>Creates the exception with a message and the error underneath it.</summary>
    public FieldGuardException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The payload names a key the ring does not have. Usually means a key was retired too early,
/// or the value came from a different environment.
/// </summary>
public sealed class UnknownKeyException : FieldGuardException
{
    /// <summary>Creates the exception for the key id found in the payload.</summary>
    public UnknownKeyException(string keyId)
        : base($"The value was encrypted with key '{keyId}', which is not on the key ring.")
    {
        KeyId = keyId;
    }

    /// <summary>The key id the payload asked for.</summary>
    public string KeyId { get; }
}

/// <summary>The value is not something this library produced, or it has been truncated.</summary>
public sealed class InvalidPayloadException : FieldGuardException
{
    /// <summary>Creates the exception with a message.</summary>
    public InvalidPayloadException(string message) : base(message) { }
    /// <summary>Creates the exception with a message and the error underneath it.</summary>
    public InvalidPayloadException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The payload was changed after it was written. AES-GCM detects this, which is the main
/// reason this library uses it instead of a plain AES mode.
/// </summary>
public sealed class TamperedPayloadException : FieldGuardException
{
    /// <summary>Creates the exception from the underlying cryptographic failure.</summary>
    public TamperedPayloadException(Exception inner)
        : base("The value failed its authentication check: it was modified after it was encrypted.", inner) { }
}
