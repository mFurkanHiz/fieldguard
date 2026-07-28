using System.Text;

namespace FieldGuard;

/// <summary>
/// One AES-256 key together with the id that identifies it inside a <see cref="KeyRing"/>.
/// The id is written into every payload, which is what makes key rotation possible.
/// </summary>
public sealed class EncryptionKey
{
    /// <summary>AES-256 means the key is exactly 32 bytes. Nothing else is accepted.</summary>
    public const int KeySizeInBytes = 32;

    private readonly byte[] _material;

    /// <summary>Creates a key from raw material. The material must be exactly 32 bytes.</summary>
    public EncryptionKey(string id, byte[] material)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            throw new ArgumentException("A key needs an id.", nameof(id));
        }

        ArgumentNullException.ThrowIfNull(material);

        if (material.Length != KeySizeInBytes)
        {
            throw new ArgumentException(
                $"The key must be {KeySizeInBytes} bytes (AES-256) but was {material.Length}.",
                nameof(material));
        }

        // The id goes into the payload as raw bytes with a single length byte in front,
        // so it has to stay short. 255 is far more than any sensible id needs.
        IdBytes = Encoding.UTF8.GetBytes(id);
        if (IdBytes.Length > byte.MaxValue)
        {
            throw new ArgumentException("The key id is too long, keep it under 255 bytes.", nameof(id));
        }

        Id = id;

        // Copy so the caller cannot change the key material later by holding on to the array
        _material = (byte[])material.Clone();
    }

    /// <summary>Creates a key from a Base64 string, which is how keys usually arrive from configuration.</summary>
    public static EncryptionKey FromBase64(string id, string base64Material)
    {
        ArgumentNullException.ThrowIfNull(base64Material);

        byte[] material;
        try
        {
            material = Convert.FromBase64String(base64Material);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("The key material is not valid Base64.", nameof(base64Material), ex);
        }

        return new EncryptionKey(id, material);
    }

    /// <summary>Generates a new random AES-256 key. Useful for tests and for the first key you ever create.</summary>
    public static EncryptionKey Generate(string id)
    {
        var material = new byte[KeySizeInBytes];
        System.Security.Cryptography.RandomNumberGenerator.Fill(material);
        return new EncryptionKey(id, material);
    }

    /// <summary>Identifies this key. Written into every payload so it can be found again later.</summary>
    public string Id { get; }

    internal byte[] IdBytes { get; }

    internal ReadOnlySpan<byte> Material => _material;
}
