# C#

> Additive to STANDARDS.md. Read that first. Everything here is C#/.NET-specific.
>
> Target: .NET 10 LTS, C# 14. Mouseion media management backend.
>
> **Key decisions:** Dapper (no EF Core), DryIoc DI, System.Text.Json source gen, primary constructors, CancellationToken everywhere, Polly resilience, PascalCase constants.

---

## Toolchain

- **Framework:** .NET 10 LTS
- **Language:** C# 14
- **ORM:** None. **Dapper only.** No Entity Framework Core.
- **Build/validate:**
  ```bash
  dotnet build Mouseion.sln --configuration Release
  dotnet test --configuration Release --verbosity minimal
  dotnet format --verify-no-changes
 ```

---

## Naming

See STANDARDS.md § Naming for universal conventions. C# overrides noted below.

| Element | Convention | Example |
|---------|-----------|---------|
| Files | `PascalCase.cs` | `AudiobookService.cs` |
| Interfaces | `IPascalCase` | `IMediaRepository` |
| Methods | `PascalCase` | `GetChaptersAsync`, `LoadConfig` |
| Properties | `PascalCase` | `TotalDuration`, `IsActive` |
| Private fields | `_camelCase` | `_repository`, `_cache` |
| Local variables | `camelCase` | `albumCount`, `isValid` |
| Constants | `PascalCase` (overrides UPPER_SNAKE) | `DefaultCacheTtl`, `MaxRetries` |
| Async methods | suffix `Async` | `FetchMetadataAsync`, `LoadAlbumAsync` |

---

## Type system

### Records for value types

```csharp
public record AlbumSummary(string Title, int TrackCount, TimeSpan Duration);
```

Use `record` for immutable data transfer. `record struct` for stack-allocated small types.

### Primary constructors

Use for DI injection and classes. Parameters are captured as needed, not as fields.

```csharp
public class AlbumService(IMediaRepository repository, ILogger<AlbumService> logger)
{
    public async Task<Album?> FindAsync(int id, CancellationToken ct)
    {
        logger.LogDebug("Loading album {Id}", id);
        return await repository.FindByIdAsync(id, ct);
    }
}
```

For properties that must be `readonly`, assign to an explicit `readonly` field. Primary constructor parameters are mutable captures.

### Collection expressions

```csharp
int[] ids = [1, 2, 3];
List<string> names = ["alice", "bob"];
int[] combined = [..first, ..second, 42];
```

Compiler generates optimal code (stack-allocated spans where possible). Use over `new[] { }` and `new List<T> { }`.

### `required` and `init` properties

```csharp
public class SessionConfig
{
    public required string Name { get; init; }
    public required int MaxTurns { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}
```

`required` enforces initialization at compile time. Caveat: reflection-based deserialization does not enforce `required`: use source-generated `System.Text.Json` serialization for safety.

### `field` keyword (C# 14)

Custom property logic without declaring a backing field:

```csharp
public string Name
{
    get => field;
    set => field = value?.Trim() ?? throw new ArgumentNullException(nameof(value));
}
```

### Nullable reference types

Enabled project-wide. `string?` means nullable, `string` means non-null. No `!` null-forgiving operator without explanation.

### Pattern matching

```csharp
return result switch
{
    Success<Album> s => Ok(s.Value),
    Failure<Album> { Error: NotFoundError } => NotFound(),
    Failure<Album> f => Problem(f.Error.Message),
};
```

Use exhaustive `switch` expressions. The compiler warns on unhandled cases.

### Raw string literals

Use for embedded SQL, JSON, regex: any string with quotes or backslashes:

```csharp
const string sql = """
    select id, name, created_at
    from albums
    where artist_id = @ArtistId
    """;
```

Prefer over `@""` verbatim strings and escape sequences.

### `file`-Scoped types

```csharp
file class AlbumValidator { /* ... */ }
```

Visibility restricted to the declaring file. Primary use: source generators, file-local helpers.

---

## Error handling

### Custom exception hierarchies

```csharp
public class AppException : Exception
{
    public AppException(string message, Exception? inner = null) : base(message, inner) { }
}

public class ConfigException : AppException { /* ... */ }
public class SessionException : AppException { /* ... */ }
```

### Rules

- Never `catch (Exception)` without re-throw or structured logging
- `IResult` / `Results.Problem()` for API error responses
- Include correlation ID in error responses
- Custom exception types per domain area

---

## Async & concurrency

### Async all the way

- `CancellationToken` on **all** async method signatures: no exceptions
- Never `.GetAwaiter().GetResult()`: always async all the way down
- `Task.Run()` only for CPU-bound work, never for I/O

```csharp
public async Task<Album> GetAlbumAsync(int id, CancellationToken ct)
{
    return await _repository.FindByIdAsync(id, ct);
}
```

### `ConfigureAwait(false)`

**Not needed in ASP.NET Core application code**: `SynchronizationContext` is null since ASP.NET Core 1.0.

**Still use in shared libraries** that may run in WPF, WinForms, MAUI, or legacy ASP.NET contexts:

```csharp
// Library code consumed by non-ASP.NET hosts
public async Task<byte[]> ReadAsync(CancellationToken ct)
{
    return await _stream.ReadAsync(ct).ConfigureAwait(false);
}
```

### `IAsyncEnumerable<T>` for streaming

Return `IAsyncEnumerable<T>` from endpoints for streaming results. ASP.NET Core serializes elements as they arrive.

```csharp
public async IAsyncEnumerable<TrackSummary> StreamTracksAsync(
    int albumId,
    [EnumeratorCancellation] CancellationToken ct)
{
    await foreach (var track in _repository.GetTracksAsync(albumId, ct))
    {
        yield return new TrackSummary(track.Id, track.Title, track.Duration);
    }
}
```

Items materialized one at a time: no buffering of the full result set.

### `params` collections (C# 13+)

```csharp
// Span-based params avoids heap allocation for small argument lists
public void Log(params ReadOnlySpan<string> messages) { /* ... */ }
```

---

## Data access

### Dapper only

No Entity Framework Core. No ORM magic. Explicit SQL with type-safe mapping.

- Generic repository base with type-safe queries
- Parameterized queries always: never string interpolation in SQL
- `CommandDefinition` with `CancellationToken` for cancellable queries
- Transaction scope for multi-statement operations

```csharp
public async Task<MediaItem?> FindByIdAsync(int id, CancellationToken ct)
{
    const string sql = """
        select * from media_items where id = @Id
        """;
    return await _connection.QueryFirstOrDefaultAsync<MediaItem>(
        new CommandDefinition(sql, new { Id = id }, cancellationToken: ct));
}
```

---

## Serialization

### System.Text.Json with source generation

Mandate source generation for AOT, trimmed, and high-performance scenarios. Eliminates reflection cost.

```csharp
[JsonSerializable(typeof(AlbumSummary))]
[JsonSerializable(typeof(List<TrackSummary>))]
internal partial class AppJsonContext : JsonSerializerContext;
```

Set `JsonSerializerIsReflectionEnabledByDefault` to `false` in `.csproj` to prevent accidental reflection fallback.

---

## Dependency injection

**DryIoc** container.

- Constructor injection only: no service locator pattern
- Primary constructors for DI (see Type System section)
- Interface-based registration for testability
- Scoped lifetime for request-bound services
- Singleton for stateless services and caches

---

## Resilience

**Polly** for external service calls.

- Retry with exponential backoff for transient failures
- Circuit breaker for cascading failure protection
- Timeout policies on all external HTTP calls
- Combine policies in a `PolicyWrap`

---

## Caching

- `IMemoryCache` for metadata responses (15-min default TTL)
- `FrozenDictionary<K,V>` / `FrozenSet<T>` for static lookup data built once at startup: ~50% faster reads than `Dictionary`, thread-safe by nature (immutable)
- Cache keys: deterministic, include all varying parameters
- Never cache user-specific data in shared cache
- Explicit eviction on data mutation

---

## Validation

**FluentValidation** for request DTOs.

- One validator class per request type
- Validate at the API boundary, not in business logic
- Structured error responses with field-level details

---

## Testing

- **Framework:** xUnit (or NUnit)
- **Names:** `GetAlbum_ReturnsNull_WhenNotFound`, not `Test1`
- **Mocking:** Moq or NSubstitute at interface boundaries
- **Arrange-Act-Assert** pattern in every test
- Integration tests use `WebApplicationFactory<T>` for API tests

---

## Architecture

```
src/Project.Core/    : entities, services, business logic
src/Project.Api/     : controllers/endpoints, middleware, API surface
src/Project.Common/  : shared utilities, HTTP client, DI
src/Project.Host/    : entry point, configuration
tests/               : unit and integration tests
```

- Core has no dependency on Api or Host
- Api depends on Core, never the reverse
- Common is a leaf: imported by all, imports nothing project-specific
- Minimal APIs for focused endpoints (health checks, webhooks). Controllers for complex modules.

---

## Anti-Patterns

1. **Entity Framework Core**: we use Dapper. No ORM magic.
2. **`.GetAwaiter().GetResult()`**: deadlock risk. Async all the way.
3. **Missing `CancellationToken`**: every async method signature
4. **Service locator**: constructor injection only
5. **`dynamic` or untyped `var`**: explicit types when non-obvious
6. **Hardcoded connection strings**: configuration injection
7. **`string.Format` over interpolation**: use `$"..."` syntax
8. **Bare `catch (Exception)`**: catch specific, log, re-throw
9. **`null!` without explanation**: fix the nullability, don't suppress it
10. **`ConfigureAwait(false)` in ASP.NET Core app code**: unnecessary noise, no `SynchronizationContext` exists
11. **Reflection-based JSON serialization in AOT/trimmed builds**: use `System.Text.Json` source generation
12. **`new[] { }` / `new List<T> { }`**: use collection expressions: `[1, 2, 3]`
