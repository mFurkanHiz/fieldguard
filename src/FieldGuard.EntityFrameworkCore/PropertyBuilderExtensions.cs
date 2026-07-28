using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace FieldGuard.EntityFrameworkCore;

/// <summary>Adds FieldGuard to the EF Core model builder.</summary>
public static class PropertyBuilderExtensions
{
    /// <summary>
    /// Stores this property encrypted.
    /// <code>
    /// modelBuilder.Entity&lt;Customer&gt;()
    ///     .Property(c =&gt; c.NationalId)
    ///     .IsEncrypted(cipher);
    /// </code>
    /// <para>
    /// Works on both <c>string</c> and <c>string?</c> properties. It is generic rather than two
    /// overloads because nullable and non-nullable strings are the same type at runtime, so two
    /// overloads would not compile, yet a nullable property produces a
    /// <c>PropertyBuilder&lt;string?&gt;</c> that will not bind to a
    /// <c>PropertyBuilder&lt;string&gt;</c> parameter.
    /// </para>
    /// <para>
    /// The column has to be wide enough for the payload, which is longer than the plain value:
    /// roughly <c>((plaintext + key id + 30) / 3) * 4</c> characters once Base64 encoded. Give
    /// it plenty of room, or use nvarchar(max).
    /// </para>
    /// </summary>
    /// <exception cref="NotSupportedException">The property is not a string.</exception>
    public static PropertyBuilder<TProperty> IsEncrypted<TProperty>(
        this PropertyBuilder<TProperty> builder,
        IFieldCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(cipher);

        if (typeof(TProperty) != typeof(string))
        {
            throw new NotSupportedException(
                $"FieldGuard encrypts string properties, but '{typeof(TProperty).Name}' was given. " +
                "Convert the value to a string first, or encrypt the bytes yourself with IFieldCipher.");
        }

        return builder.HasConversion((ValueConverter)new EncryptedStringConverter(cipher));
    }
}
