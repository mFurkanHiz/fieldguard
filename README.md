# FieldGuard

![CI](https://github.com/mFurkanHiz/fieldguard/actions/workflows/ci.yml/badge.svg)

Encrypt individual database columns in .NET, with key rotation that does not mean rewriting
your table.

```csharp
modelBuilder.Entity<Customer>()
    .Property(c => c.NationalId)
    .IsEncrypted(cipher);
```

That is the whole integration. Your entity still has a `string NationalId`, your code still
reads and writes it as text, and the column holds ciphertext.

## Why I wrote it

I had to store national id numbers and phone numbers in a project, and "just encrypt the
column" turned out to be less simple than it sounds. The three questions that took the time:

**What happens when the key changes?** Every guide shows you `Encrypt(text, key)`. None of
them say what to do a year later when that key has to be replaced and the table already has a
million rows written with the old one.

**How do you know the value was not edited?** With AES-CBC, if someone changes bytes in the
column, decryption happily returns different text. You get corrupted data and no error.

**What happens in two years?** If the algorithm ever needs to change, every existing value has
to still be readable, which means the format has to say which version wrote it.

FieldGuard is those three answers wrapped around .NET's own AES-GCM. It is deliberately small.

## What it is not

**It is not a new cipher.** Everything cryptographic here is `System.Security.Cryptography.AesGcm`
from the .NET runtime. This library decides the format, manages the keys and picks safe
defaults. If you were hoping for a home-made algorithm, you should be glad you will not find
one.

**It is not a key manager.** Keys come from wherever you keep secrets, and getting them to the
application is your job. In production that should be Azure Key Vault, AWS KMS, or something
like them, not appsettings.json.

**It is not searchable encryption.** See the limitations at the bottom.

## Install

```
dotnet add package FieldGuard
dotnet add package FieldGuard.EntityFrameworkCore   # only if you use EF Core
```

The core package has no dependencies at all. EF Core is a separate package so that people who
just want to encrypt a value are not forced to reference it.

## Using it without EF Core

```csharp
var key = EncryptionKey.FromBase64("2026-01", config["Encryption:Key"]);
var cipher = new FieldCipher(new KeyRing(key));

var stored = cipher.Encrypt("12345678901");
var back   = cipher.Decrypt(stored);       // "12345678901"
```

To create your first key:

```csharp
Console.WriteLine(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
```

## Using it with EF Core

Give the context a cipher and mark the properties:

```csharp
public class CustomerContext : DbContext
{
    private readonly IFieldCipher _cipher;

    public CustomerContext(DbContextOptions<CustomerContext> options, IFieldCipher cipher)
        : base(options) => _cipher = cipher;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Customer>().Property(c => c.NationalId).IsEncrypted(_cipher);
        modelBuilder.Entity<Customer>().Property(c => c.Notes).IsEncrypted(_cipher);
    }
}
```

Nullable properties work too. A null stays null in the database rather than becoming an
encrypted empty string.

Make the column wide enough. The payload is longer than the plain value, so a `nvarchar(20)`
column that used to hold an id number will not fit its ciphertext.

## Key rotation

This is the part that usually gets left out.

Every payload carries the id of the key that wrote it. A key ring has one active key for
writing and any number of older keys kept for reading:

```csharp
var ring = new KeyRing(
    activeKey:   EncryptionKey.FromBase64("2026-01", newKey),   // new values use this
    retiredKeys: EncryptionKey.FromBase64("2024-06", oldKey));  // old values still readable
```

So rotating a key is: generate a new one, make it active, keep the old one on the ring. No
downtime and no migration script. Rows re-encrypt themselves onto the new key whenever
something saves them, and you can force the rest with a background job that reads and writes
each row.

Only drop the old key once nothing is using it any more. If you drop it too early you get an
`UnknownKeyException` that names the missing key, rather than a decryption failure that tells
you nothing.

## The payload format

```
version (1) | key id length (1) | key id (n) | nonce (12) | tag (16) | ciphertext
```

Base64 encoded for storage in a text column.

A few decisions worth explaining:

**AES-256-GCM, not CBC.** GCM authenticates as well as encrypts. The 16-byte tag is what makes
tampering fail loudly. There is a test for exactly this: flip one bit in a stored value and
reading it throws `TamperedPayloadException` instead of returning nonsense.

**A random nonce every time.** Encrypting the same value twice gives two different payloads.
That costs you the ability to search, and buys the guarantee that nobody can tell which rows
share a value just by looking at the table. Reusing a nonce is the one mistake that genuinely
breaks GCM, so it is never derived from the data.

**A version byte.** It does nothing today. It exists so that FieldGuard 2 can change the
algorithm and still read everything version 1 wrote.

## Tests

```
dotnet test
```

36 tests. The ones that matter are not the round trips, they are the failures: a modified
ciphertext, a modified nonce, a truncated payload, a key that is not on the ring, text that
was never encrypted, and a value written before a rotation being read after it.

The EF Core tests run against a real SQLite database rather than the in-memory provider,
because the actual question is what ends up in the column, and the in-memory provider never
stores anything.

## Known limitations

**You cannot query an encrypted column.** No `WHERE NationalId = ...`, no `LIKE`, no index that
means anything. Every payload is different, so the comparison can never match. If you need to
look values up, keep a separate blind index column holding an HMAC of the normalised value and
search on that instead. FieldGuard does not do this for you.

**Deterministic mode is not supported, on purpose.** It would make the column searchable, and
it would also let anyone reading the table see which rows share a value. For a column like a
national id that is most of what you were trying to hide.

**Strings only.** Numbers and dates would have to be converted to text first, which loses the
column type. Use `IFieldCipher` directly on the bytes if you need that.

**Sorting and ranges are gone too.** An encrypted date column cannot be ordered or filtered by
range in SQL.

**Nothing wipes keys from memory.** Key material sits in a managed byte array like any other,
and .NET can move it around. If your threat model includes someone reading process memory, this
library is not enough on its own.

## License

MIT — see [LICENSE](LICENSE).
