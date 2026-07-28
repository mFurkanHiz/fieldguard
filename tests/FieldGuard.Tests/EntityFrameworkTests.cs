using FieldGuard.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FieldGuard.Tests;

public class Customer
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string NationalId { get; set; } = "";
    public string? Notes { get; set; }
}

public class CustomerContext : DbContext
{
    private readonly IFieldCipher _cipher;

    public CustomerContext(DbContextOptions<CustomerContext> options, IFieldCipher cipher) : base(options)
    {
        _cipher = cipher;
    }

    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Customer>().Property(c => c.NationalId).IsEncrypted(_cipher);
        modelBuilder.Entity<Customer>().Property(c => c.Notes).IsEncrypted(_cipher);
        // Name is deliberately left alone, to prove only the marked columns change
    }
}

/// <summary>
/// These run against a real SQLite database rather than the in-memory provider, because the
/// whole question is what ends up in the actual column. The in-memory provider never stores
/// anything, so it could not answer that.
/// </summary>
public class EntityFrameworkTests : IDisposable
{
    private readonly SqliteConnection _connection;
    private readonly DbContextOptions<CustomerContext> _options;
    private readonly KeyRing _ring = new(EncryptionKey.Generate("k1"));

    public EntityFrameworkTests()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();
        _options = new DbContextOptionsBuilder<CustomerContext>().UseSqlite(_connection).Options;

        using var db = new CustomerContext(_options, new FieldCipher(_ring));
        db.Database.EnsureCreated();
    }

    private CustomerContext NewContext(KeyRing? ring = null) =>
        new(_options, new FieldCipher(ring ?? _ring));

    [Fact]
    public void The_value_is_readable_through_the_context()
    {
        using (var db = NewContext())
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "12345678901", Notes = "vip" });
            db.SaveChanges();
        }

        using (var db = NewContext())
        {
            var customer = db.Customers.Single();

            Assert.Equal("Ada", customer.Name);
            Assert.Equal("12345678901", customer.NationalId);
            Assert.Equal("vip", customer.Notes);
        }
    }

    [Fact]
    public void The_value_in_the_column_is_not_the_plaintext()
    {
        using (var db = NewContext())
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "12345678901" });
            db.SaveChanges();
        }

        // Read the raw column, going around EF entirely
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Name, NationalId FROM Customers";
        using var reader = command.ExecuteReader();
        reader.Read();

        Assert.Equal("Ada", reader.GetString(0));                 // untouched column
        Assert.NotEqual("12345678901", reader.GetString(1));      // encrypted column
        Assert.DoesNotContain("12345678901", reader.GetString(1));
    }

    [Fact]
    public void Null_stays_null_in_the_database()
    {
        using (var db = NewContext())
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "1", Notes = null });
            db.SaveChanges();
        }

        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Notes FROM Customers";
        Assert.Equal(DBNull.Value, command.ExecuteScalar());
    }

    [Fact]
    public void A_row_written_before_rotation_is_still_readable_after_it()
    {
        var oldKey = EncryptionKey.Generate("2024");
        var newKey = EncryptionKey.Generate("2025");

        using (var db = NewContext(new KeyRing(oldKey)))
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "12345678901" });
            db.SaveChanges();
        }

        using (var db = NewContext(new KeyRing(newKey, oldKey)))
        {
            Assert.Equal("12345678901", db.Customers.Single().NationalId);
        }
    }

    [Fact]
    public void Someone_editing_the_column_by_hand_is_caught_on_read()
    {
        using (var db = NewContext())
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "12345678901" });
            db.SaveChanges();
        }

        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "UPDATE Customers SET NationalId = 'tampered'";
            command.ExecuteNonQuery();
        }

        using var db2 = NewContext();
        Assert.Throws<InvalidPayloadException>(() => db2.Customers.Single());
    }

    [Fact]
    public void An_encrypted_column_cannot_be_filtered_in_the_database()
    {
        // Worth pinning down because it surprises people. Every payload is different, so a
        // WHERE on the encrypted column can never match. EF pushes this down to SQL and
        // simply finds nothing.
        using (var db = NewContext())
        {
            db.Customers.Add(new Customer { Name = "Ada", NationalId = "12345678901" });
            db.SaveChanges();
        }

        using var db3 = NewContext();

        Assert.Empty(db3.Customers.Where(c => c.NationalId == "12345678901"));
        Assert.Single(db3.Customers.AsEnumerable().Where(c => c.NationalId == "12345678901"));
    }

    public void Dispose() => _connection.Dispose();
}

public class NonStringProperty
{
    public int Id { get; set; }
    public decimal Salary { get; set; }
}

public class NonStringContext : DbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder options) =>
        options.UseSqlite("DataSource=:memory:");

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.Entity<NonStringProperty>()
            .Property(x => x.Salary)
            .IsEncrypted(new FieldCipher(new KeyRing(EncryptionKey.Generate("k1"))));
}

public class UnsupportedPropertyTests
{
    [Fact]
    public void Marking_a_non_string_property_says_so_instead_of_failing_later()
    {
        using var db = new NonStringContext();

        var ex = Assert.Throws<NotSupportedException>(() => db.Model.GetHashCode());

        Assert.Contains("Decimal", ex.Message);
    }
}
