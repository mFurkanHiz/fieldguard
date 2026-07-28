namespace FieldGuard.Tests;

public class KeyRotationTests
{
    private static readonly EncryptionKey Old = EncryptionKey.Generate("2024-01");
    private static readonly EncryptionKey New = EncryptionKey.Generate("2025-06");

    [Fact]
    public void After_rotating_old_values_are_still_readable()
    {
        // What rotation has to survive: the database is full of values written months ago
        // with a key that is no longer the active one.
        var before = new FieldCipher(new KeyRing(Old));
        var written = before.Encrypt("written last year");

        var after = new FieldCipher(new KeyRing(New, Old));

        Assert.Equal("written last year", after.Decrypt(written));
    }

    [Fact]
    public void After_rotating_new_values_use_the_new_key()
    {
        var cipher = new FieldCipher(new KeyRing(New, Old));

        var payload = Convert.FromBase64String(cipher.Encrypt("written today")!);
        var keyIdLength = payload[1];
        var keyId = System.Text.Encoding.UTF8.GetString(payload, 2, keyIdLength);

        Assert.Equal("2025-06", keyId);
    }

    [Fact]
    public void Retiring_a_key_too_early_gives_a_useful_error()
    {
        // The failure people actually hit: the old key is dropped from configuration while
        // rows encrypted with it are still in the table. The message has to name the key.
        var written = new FieldCipher(new KeyRing(Old)).Encrypt("written last year");
        var afterDroppingTheOldKey = new FieldCipher(new KeyRing(New));

        var ex = Assert.Throws<UnknownKeyException>(() => afterDroppingTheOldKey.Decrypt(written));

        Assert.Equal("2024-01", ex.KeyId);
        Assert.Contains("2024-01", ex.Message);
    }

    [Fact]
    public void A_ring_reports_every_key_it_can_read()
    {
        var ring = new KeyRing(New, Old);

        Assert.Equal(new[] { "2024-01", "2025-06" }, ring.KnownKeyIds.OrderBy(x => x));
    }

    [Fact]
    public void Two_keys_cannot_share_an_id()
    {
        var duplicate = EncryptionKey.Generate("2025-06");

        Assert.Throws<ArgumentException>(() => new KeyRing(New, duplicate));
    }

    [Fact]
    public void Re_encrypting_moves_a_value_onto_the_active_key()
    {
        // How a background job would migrate old rows: read with the ring, write back.
        var cipher = new FieldCipher(new KeyRing(New, Old));
        var oldPayload = new FieldCipher(new KeyRing(Old)).Encrypt("customer record");

        var rewritten = cipher.Encrypt(cipher.Decrypt(oldPayload));

        var raw = Convert.FromBase64String(rewritten!);
        var keyId = System.Text.Encoding.UTF8.GetString(raw, 2, raw[1]);

        Assert.Equal("2025-06", keyId);
        Assert.Equal("customer record", cipher.Decrypt(rewritten));
    }
}

public class EncryptionKeyTests
{
    [Theory]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(0)]
    public void Only_a_256_bit_key_is_accepted(int size)
    {
        Assert.Throws<ArgumentException>(() => new EncryptionKey("k", new byte[size]));
    }

    [Fact]
    public void A_key_needs_an_id()
    {
        Assert.Throws<ArgumentException>(() => new EncryptionKey("  ", new byte[32]));
    }

    [Fact]
    public void A_key_can_be_read_from_base64_configuration()
    {
        var material = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(material);

        var key = EncryptionKey.FromBase64("from-config", Convert.ToBase64String(material));
        var cipher = new FieldCipher(new KeyRing(key));

        Assert.Equal("from-config", key.Id);
        Assert.Equal("value", cipher.Decrypt(cipher.Encrypt("value")));
    }

    [Fact]
    public void Rubbish_in_configuration_is_reported_clearly()
    {
        Assert.Throws<ArgumentException>(() => EncryptionKey.FromBase64("k", "not base64 at all!!"));
    }

    [Fact]
    public void Changing_the_array_afterwards_does_not_change_the_key()
    {
        var material = new byte[32];
        var key = new EncryptionKey("k", material);
        var cipher = new FieldCipher(new KeyRing(key));
        var payload = cipher.Encrypt("value");

        material[0] = 0xFF;   // the caller mutates the array they passed in

        Assert.Equal("value", cipher.Decrypt(payload));
    }
}
