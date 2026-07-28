using System.Text;

namespace FieldGuard.Tests;

public class FieldCipherTests
{
    private static FieldCipher NewCipher(string keyId = "k1") =>
        new(new KeyRing(EncryptionKey.Generate(keyId)));

    [Theory]
    [InlineData("hello")]
    [InlineData("12345678901")]
    [InlineData("Ünicode ile Türkçe karakterler")]
    [InlineData("a very long value that goes on and on and on, well past a single AES block boundary")]
    public void What_goes_in_comes_back_out(string plaintext)
    {
        var cipher = NewCipher();

        Assert.Equal(plaintext, cipher.Decrypt(cipher.Encrypt(plaintext)));
    }

    [Fact]
    public void The_payload_does_not_contain_the_plaintext()
    {
        var cipher = NewCipher();

        var payload = cipher.Encrypt("4111111111111111")!;

        Assert.DoesNotContain("4111", payload);
        Assert.DoesNotContain("4111", Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
    }

    [Fact]
    public void Encrypting_the_same_value_twice_gives_two_different_payloads()
    {
        // This is the point of the random nonce. If encryption were deterministic, anyone
        // reading the table could see which rows share a value, without decrypting anything.
        var cipher = NewCipher();

        var first = cipher.Encrypt("same input");
        var second = cipher.Encrypt("same input");

        Assert.NotEqual(first, second);
        Assert.Equal("same input", cipher.Decrypt(first));
        Assert.Equal("same input", cipher.Decrypt(second));
    }

    [Fact]
    public void Null_and_empty_are_left_alone()
    {
        var cipher = NewCipher();

        Assert.Null(cipher.Encrypt(null));
        Assert.Equal("", cipher.Encrypt(""));
        Assert.Null(cipher.Decrypt(null));
        Assert.Equal("", cipher.Decrypt(""));
    }

    [Fact]
    public void A_modified_payload_is_rejected()
    {
        // The reason for GCM instead of CBC. Flip one bit in the ciphertext and decryption
        // must fail, not quietly return something that looks like data.
        var cipher = NewCipher();
        var raw = Convert.FromBase64String(cipher.Encrypt("transfer 100")!);

        raw[^1] ^= 0x01;

        Assert.Throws<TamperedPayloadException>(() => cipher.Decrypt(Convert.ToBase64String(raw)));
    }

    [Fact]
    public void A_modified_nonce_is_rejected()
    {
        var cipher = NewCipher();
        var raw = Convert.FromBase64String(cipher.Encrypt("transfer 100")!);

        // 2 header bytes + 2 bytes of key id "k1", so the nonce starts at index 4
        raw[4] ^= 0x01;

        Assert.Throws<TamperedPayloadException>(() => cipher.Decrypt(Convert.ToBase64String(raw)));
    }

    [Fact]
    public void A_payload_from_a_different_key_cannot_be_read()
    {
        var written = NewCipher("k1").Encrypt("secret")!;
        var other = new FieldCipher(new KeyRing(EncryptionKey.Generate("k1")));  // same id, different material

        Assert.Throws<TamperedPayloadException>(() => other.Decrypt(written));
    }

    [Fact]
    public void Text_that_was_never_encrypted_is_reported_clearly()
    {
        var cipher = NewCipher();

        Assert.Throws<InvalidPayloadException>(() => cipher.Decrypt("this is just a sentence"));
    }

    [Fact]
    public void A_truncated_payload_is_reported_clearly()
    {
        var cipher = NewCipher();
        var raw = Convert.FromBase64String(cipher.Encrypt("secret")!);

        var truncated = raw.AsSpan(0, 6).ToArray();

        Assert.Throws<InvalidPayloadException>(() => cipher.Decrypt(Convert.ToBase64String(truncated)));
    }

    [Fact]
    public void A_payload_from_a_future_version_is_refused_rather_than_guessed_at()
    {
        var cipher = NewCipher();
        var raw = Convert.FromBase64String(cipher.Encrypt("secret")!);

        raw[0] = 99;

        var ex = Assert.Throws<InvalidPayloadException>(() => cipher.Decrypt(Convert.ToBase64String(raw)));
        Assert.Contains("99", ex.Message);
    }

    [Fact]
    public void Bytes_round_trip_as_well_as_text()
    {
        var cipher = NewCipher();
        var original = new byte[] { 0, 1, 2, 253, 254, 255 };

        Assert.Equal(original, cipher.DecryptBytes(cipher.EncryptBytes(original)));
    }

    [Fact]
    public void An_empty_byte_array_round_trips()
    {
        var cipher = NewCipher();

        Assert.Empty(cipher.DecryptBytes(cipher.EncryptBytes([])));
    }
}
