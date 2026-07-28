using System.Security.Cryptography;
using System.Text;

namespace FieldGuard;

/// <summary>Encrypts and decrypts single values, such as one database column.</summary>
public interface IFieldCipher
{
    /// <summary>Encrypts text and returns a Base64 payload. Null and empty come back unchanged.</summary>
    string? Encrypt(string? plaintext);

    /// <summary>Decrypts a payload produced by <see cref="Encrypt"/>. Null and empty come back unchanged.</summary>
    string? Decrypt(string? payload);

    /// <summary>Encrypts raw bytes and returns the payload, header included.</summary>
    byte[] EncryptBytes(ReadOnlySpan<byte> plaintext);

    /// <summary>Decrypts a payload produced by <see cref="EncryptBytes"/>.</summary>
    byte[] DecryptBytes(ReadOnlySpan<byte> payload);
}

/// <summary>
/// AES-256-GCM encryption for individual values.
/// <para>
/// GCM is used rather than a plain mode such as CBC because it authenticates as well as
/// encrypts. If someone edits a ciphertext in the database, decryption fails loudly instead of
/// returning plausible-looking rubbish.
/// </para>
/// <para>
/// The payload is laid out as:
/// <code>
/// version (1 byte) | key id length (1 byte) | key id (n bytes) | nonce (12) | tag (16) | ciphertext
/// </code>
/// The version byte is what lets a later release change the algorithm while still reading
/// everything written by this one. The key id is what makes rotation possible.
/// </para>
/// </summary>
public sealed class FieldCipher : IFieldCipher
{
    private const byte CurrentVersion = 1;
    private const int NonceSize = 12;   // 96 bits, the size GCM is designed around
    private const int TagSize = 16;     // 128 bits, the largest GCM offers

    private readonly KeyRing _keyRing;

    /// <summary>Creates a cipher that encrypts with the ring's active key and decrypts with any of its keys.</summary>
    public FieldCipher(KeyRing keyRing)
    {
        _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
    }

    /// <inheritdoc />
    public string? Encrypt(string? plaintext)
    {
        // An empty column stays empty. Encrypting "" would still produce a payload and would
        // tell an observer that the row has a value there, which is the opposite of the point.
        if (string.IsNullOrEmpty(plaintext))
        {
            return plaintext;
        }

        var bytes = Encoding.UTF8.GetBytes(plaintext);
        return Convert.ToBase64String(EncryptBytes(bytes));
    }

    /// <inheritdoc />
    public string? Decrypt(string? payload)
    {
        if (string.IsNullOrEmpty(payload))
        {
            return payload;
        }

        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(payload);
        }
        catch (FormatException ex)
        {
            throw new InvalidPayloadException("The value is not valid Base64, so it was not written by FieldGuard.", ex);
        }

        return Encoding.UTF8.GetString(DecryptBytes(raw));
    }

    /// <inheritdoc />
    public byte[] EncryptBytes(ReadOnlySpan<byte> plaintext)
    {
        var key = _keyRing.ActiveKey;
        var keyId = key.IdBytes;

        var result = new byte[2 + keyId.Length + NonceSize + TagSize + plaintext.Length];

        result[0] = CurrentVersion;
        result[1] = (byte)keyId.Length;
        keyId.CopyTo(result.AsSpan(2));

        var nonce = result.AsSpan(2 + keyId.Length, NonceSize);
        var tag = result.AsSpan(2 + keyId.Length + NonceSize, TagSize);
        var ciphertext = result.AsSpan(2 + keyId.Length + NonceSize + TagSize);

        // A fresh random nonce every single time. Reusing one with the same key is the one
        // mistake that genuinely breaks GCM, so it is never derived from the data.
        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(key.Material, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return result;
    }

    /// <inheritdoc />
    public byte[] DecryptBytes(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 2)
        {
            throw new InvalidPayloadException("The value is too short to be a FieldGuard payload.");
        }

        var version = payload[0];
        if (version != CurrentVersion)
        {
            throw new InvalidPayloadException(
                $"Payload version {version} is not supported by this version of FieldGuard.");
        }

        int keyIdLength = payload[1];
        var headerLength = 2 + keyIdLength + NonceSize + TagSize;
        if (payload.Length < headerLength)
        {
            throw new InvalidPayloadException("The value is shorter than its own header says it should be.");
        }

        var keyId = Encoding.UTF8.GetString(payload.Slice(2, keyIdLength));
        if (!_keyRing.TryGet(keyId, out var key))
        {
            throw new UnknownKeyException(keyId);
        }

        var nonce = payload.Slice(2 + keyIdLength, NonceSize);
        var tag = payload.Slice(2 + keyIdLength + NonceSize, TagSize);
        var ciphertext = payload[headerLength..];

        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key.Material, TagSize);
        try
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new TamperedPayloadException(ex);
        }

        return plaintext;
    }
}
