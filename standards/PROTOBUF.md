# Protocol Buffers

> Standards for proto3 schema design, wire compatibility, and Rust codegen. Applies to all `.proto` files and generated code.

---

## File organization

- One file per service. Service file named after the service in `lower_snake_case.proto`.
- Supporting messages and enums shared across services go in dedicated files grouped by domain.
- File order: syntax, package, imports (sorted alphabetically), file options (sorted), definitions.
- Directory structure mirrors package path: `package foo.bar.v1;` lives in `foo/bar/v1/`.
- Keep files under 500 lines. Split large domains into multiple files within the same package.

## Package naming

- Dot-delimited `lower_snake_case`: `meshtastic`, `akroasis.kerykeion.v1`.
- No uppercase letters, no emphasizes within segments, no Java-style `com.` prefixes.
- Stable packages end with a version suffix: `v1`, `v2`. Pre-release: `v1alpha1`, `v1beta2`.
- Stable packages never import unstable packages.

## Syntax

- All files declare `syntax = "proto3";` as the first non-comment line.

## Naming conventions

### Messages

- `PascalCase`: `MeshPacket`, `DeviceMetrics`, `ChannelSettings`.
- Request/response types: `{MethodName}Request` / `{MethodName}Response`.
- Treat abbreviations as single words: `GetDnsRequest` not `GetDNSRequest`.
- Never start or end a name with emphasize.

### Fields

- `snake_case`: `battery_level`, `channel_utilization`, `rx_snr`.
- Repeated fields use plural names: `repeated uint32 route = 2;`.
- Boolean fields use `is_` or `has_` prefix when it improves clarity: `is_licensed`, `has_default_channel`.
- Avoid language keywords (`type`, `class`, `default`) as field names -- codegen renames them.

### Enums

- Type name: `PascalCase`: `HardwareModel`, `PortNum`.
- Values: `UPPER_SNAKE_CASE` prefixed with the enum type name: `HARDWARE_MODEL_UNSET`, `PORT_NUM_UNKNOWN_APP`.
- Prefix prevents C++ global scope collisions and clarifies meaning in languages without enum scoping.
- Exception: project-wide enums where the prefix would be redundant and values are unambiguous may omit the prefix if every consumer imports only that enum.

### Services and rPCs

- Service name: `PascalCase`, suffixed with `Service`: `TelemetryService`, `AdminService`.
- RPC methods: `PascalCase` using `VerbNoun` pattern: `GetChannel`, `ListNodes`, `CreateSession`.

### Oneofs

- `snake_case`: `payload_variant`, `config_type`.
- Consistent naming within a project -- pick one convention and use it everywhere.

## Field numbering

- Numbers 1–15 encode as one byte on the wire. Reserve these for frequently-set fields.
- Numbers 16–2047 encode as two bytes. Use for less common fields.
- Never reuse a field number, even after deleting the field. Serialized data in logs, caches, and storage may still reference old numbers.
- Reserve deleted field numbers AND names to prevent accidental reuse:

```protobuf
reserved 6, 9;
reserved "old_field", "deprecated_field";
```

- Number gaps are acceptable when fields have been removed and reserved. Document with a comment above the `reserved` block.
- Field numbers above 19000–19999 are reserved by the protobuf implementation. Never use them.

## Backwards compatibility

Protobuf's value is schema evolution. Breaking the wire format negates the reason to use it.

### Safe changes (additive only)

- Add new fields, enum values, messages, services, RPCs, oneofs.
- Rename fields (wire format uses numbers, not names -- but JSON encoding uses names, so avoid renaming in JSON-facing APIs).
- Add `reserved` entries for removed fields.

### Breaking changes (never within a major version)

- Remove or renumber existing fields.
- Change a field's type (even between wire-compatible types like `int32` → `int64` -- codegen types differ).
- Move a field into or out of a `oneof` (breaks Go stubs, loses data on other platforms).
- Change `repeated` to scalar or vice versa.
- Change the default value of a field.
- Remove an enum value that clients may have persisted.
- Delete a file or move a message to a different file (breaks per-file codegen).

### Deprecation

- Mark deprecated fields with `[deprecated = true]`.
- Add a comment explaining what replaces it.
- Reserve the field number and name when the field is finally removed.

## Enum conventions

- First value is always zero and signals "unset": `FOO_UNSPECIFIED = 0` or `FOO_UNKNOWN = 0`.
- Every enum has a zero value. Proto3 uses zero as the default -- without an explicit unspecified value, the first real value becomes the ambiguous default.
- Assign values sequentially. Gaps only where values were removed and reserved.
- Never use `allow_alias` -- aliased values cause JSON serialization ambiguity.
- Never use negative enum values.
- Prefer enums over booleans when the domain may grow beyond two states.

## Service design

- Each RPC has unique request and response types. Never share `{Method}Request` across RPCs -- it couples their evolution.
- Use unary RPCs by default. Use streaming only when the use case demands it (real-time feeds, large transfers, bidirectional communication).
- Map domain errors to gRPC status codes consistently. Document the mapping.
- Standard CRUD methods: `Get`, `List`, `Create`, `Update`, `Delete`.
- Long-running operations return an `Operation` message with status polling.

## Import conventions

- Use package-relative paths: `import "meshtastic/mesh.proto";`.
- Never use `import public` -- it pollutes the dependency graph across transitive consumers.
- Never use `import weak`.
- Sort imports alphabetically.
- Remove unused imports.
- Avoid circular imports between packages.

## Documentation

- Leading `//` comment on every message, enum, service, and RPC. At least one complete sentence.
- Leading `//` comment on every field that isn't self-explanatory from its name and type.
- Comments describe purpose and constraints, not the type (the schema already says that).
- Document units for numeric fields: `// Altitude in metres above sea level.`
- Document valid ranges or special sentinel values: `// 0 means unset; valid range 1–255.`

## Wire format considerations

### Type selection

| Use case | Type | Encoding |
|----------|------|----------|
| Positive integers, usually small | `uint32` / `uint64` | Varint |
| Integers that are often negative | `sint32` / `sint64` | ZigZag varint |
| Integers that are always large (>2^28) | `fixed32` / `fixed64` | Fixed-width |
| Latitude/longitude in integer degrees | `sfixed32` | Fixed-width (4 bytes always) |
| Flags, small counts | `uint32` | Varint |
| Timestamps | `google.protobuf.Timestamp` | Well-known type |
| Durations | `google.protobuf.Duration` | Well-known type |

- Use well-known types (`Timestamp`, `Duration`, `FieldMask`, `Any`, `Struct`) over custom integer fields for standard concepts.
- `repeated` scalar fields use packed encoding by default in proto3. No action needed.
- `bytes` for opaque binary data. `string` must be valid UTF-8.

### Size discipline

- Keep individual messages under 1 MB. Protobuf is not designed for bulk data transfer.
- Avoid messages with more than 100 fields -- they bloat memory and hit codegen limits in some languages.
- Use streaming RPCs for large result sets instead of single giant response messages.

## Rust codegen patterns

### Build configuration

```rust
// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/service.proto"], &["proto/"])?;
    Ok(())
}
```

### Type extensions

- Never modify generated code directly. Extend in separate `_ext.rs` files with `impl` blocks.
- Use `Config::type_attribute` and `Config::field_attribute` to inject derives (`serde::Serialize`, `Hash`, `Eq`) at build time.

### Domain conversion

- Implement `From<ProtoType>` / `TryFrom<ProtoType>` between proto types and domain types.
- Validate at the conversion boundary. Proto types are permissive (all fields optional in proto3). Domain types enforce invariants.
- Keep proto types out of business logic. Convert at the edge (handler entry, client call site).

### Error mapping

- Map gRPC status codes to domain errors via `impl From<ServiceError> for tonic::Status`.
- Include structured details in `tonic::Status::with_details()` for machine-readable error context.

## Anti-patterns

| Anti-pattern | Problem | Alternative |
|-------------|---------|-------------|
| Reusing field numbers after deletion | Silent data corruption from old serialized data | `reserved` the number and name |
| Changing field types | Breaks deserialization across versions | Add a new field, deprecate the old one |
| Missing enum zero value | First real value becomes ambiguous default | Always define `_UNSPECIFIED = 0` |
| `import public` | Transitive dependency pollution | Direct imports only |
| `allow_alias` on enums | JSON serialization ambiguity | One name per number |
| Boolean for extensible state | Locked to two values forever | Enum with `UNSPECIFIED` zero |
| Shared request/response types across RPCs | Couples independent evolution | Unique types per RPC |
| Hundreds of fields per message | Memory bloat, codegen limits | Split into nested messages |
| Modifying generated code | Overwritten on next build | Extension files with `impl` blocks |
| Text format for interchange | Breaks on any field rename | Binary or JSON encoding |
| `oneof` field migration | Moving fields in/out breaks Go stubs and loses data | Treat `oneof` membership as permanent |
| Stringly-typed fields for structured data | No validation, no evolution | Nested message or enum |
