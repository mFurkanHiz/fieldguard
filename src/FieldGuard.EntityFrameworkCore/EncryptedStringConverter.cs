using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace FieldGuard.EntityFrameworkCore;

/// <summary>
/// Converts a property to its encrypted form on the way into the database and back again on
/// the way out. EF Core applies it inside its own read and write pipeline, so entity code and
/// queries keep working with the plain value.
/// <para>
/// The converter is declared over non-nullable strings on purpose. EF Core handles nulls
/// before a converter is called, so a null column never reaches this code and stays null in
/// the database rather than turning into an encrypted empty string.
/// </para>
/// </summary>
public sealed class EncryptedStringConverter : ValueConverter<string, string>
{
    /// <summary>Creates a converter that uses the given cipher for both directions.</summary>
    public EncryptedStringConverter(IFieldCipher cipher)
        : base(
            plaintext => cipher.Encrypt(plaintext)!,
            stored => cipher.Decrypt(stored)!)
    {
    }
}
