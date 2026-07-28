namespace FieldGuard;

/// <summary>
/// The set of keys the application knows about.
/// <para>
/// New values are always encrypted with the active key. Old values keep working because every
/// payload carries the id of the key it was written with, and decryption looks that id up here.
/// Rotating a key therefore means adding a new one and making it active, not rewriting the
/// database. Old rows re-encrypt themselves the next time something saves them.
/// </para>
/// </summary>
public sealed class KeyRing
{
    private readonly Dictionary<string, EncryptionKey> _keys;

    /// <summary>Creates a ring with one active key and any number of older keys kept for reading.</summary>
    public KeyRing(EncryptionKey activeKey, params EncryptionKey[] retiredKeys)
    {
        ArgumentNullException.ThrowIfNull(activeKey);
        ArgumentNullException.ThrowIfNull(retiredKeys);

        ActiveKey = activeKey;

        _keys = new Dictionary<string, EncryptionKey>(StringComparer.Ordinal)
        {
            [activeKey.Id] = activeKey
        };

        foreach (var key in retiredKeys)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (!_keys.TryAdd(key.Id, key))
            {
                throw new ArgumentException($"There is more than one key with the id '{key.Id}'.", nameof(retiredKeys));
            }
        }
    }

    /// <summary>The key new values are encrypted with.</summary>
    public EncryptionKey ActiveKey { get; }

    /// <summary>Every key id this ring can decrypt, including the active one.</summary>
    public IReadOnlyCollection<string> KnownKeyIds => _keys.Keys;

    internal bool TryGet(string keyId, out EncryptionKey key) => _keys.TryGetValue(keyId, out key!);
}
