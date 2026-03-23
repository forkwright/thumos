# Nix

> Additive to STANDARDS.md. Read that first. Everything here is Nix-specific.
>
> Covers: Nix language, flake conventions, NixOS module patterns, derivation packaging.
>
> **Key decisions:** nixfmt formatter, let-in over rec, explicit pkgs over with, Crane for Rust, .follows on transitive nixpkgs, no lookup paths.

---

## Language fundamentals

### Types

Nix has very few types. Simplicity enables reproducibility.

**Primitive types:**

| Type | Examples | Notes |
|------|----------|-------|
| String | `"hello"`, `''multi-line''` | Interpolation with `${}`. Concatenation with `+`. |
| Boolean | `true`, `false` | Only booleans work in `if`. `null` is NOT falsy. |
| Integer | `42`, `-1` | |
| Float | `3.14` | Coerces with integers automatically. |
| Null | `null` | Distinct from `false`. Signifies absence. |
| Path | `./foo.nix`, `/etc/nixos` | Built-in type, not a string. Important for flake purity. |

**Compound types:**

| Type | Syntax | Notes |
|------|--------|-------|
| Attribute set (attrset) | `{ key = value; }` | Semicolons required. The fundamental data structure. |
| List | `[ 1 "two" 3 ]` | Space-separated. Heterogeneous. Concatenation with `++`. |

### Functions

```nix
# Single argument, single return value. ALWAYS.
x: x + 1

# Application uses space (not parentheses)
(x: x + 1) 2    # => 3

# Multi-argument via currying
x: y: x + y

# Attrset destructuring (most common pattern)
{ foo, bar }: foo + bar

# With default values
{ foo, bar ? "default" }: foo + bar

# With catch-all for extra args
{ foo, bar, ... }: foo + bar
```

### Key expressions

**`let ... in`**: Local bindings. The workhorse of factoring out code.

**`if ... then ... else`**: Everything is an expression. `if` returns a value.

**`inherit`**: Shorthand for `x = x` in attrsets. NOT OOP inheritance.

**`with`**: Brings attrset keys into scope. Use sparingly (see anti-patterns).

**`//`**: Shallow merge of attrsets. Right takes precedence. WARNING: nested attrsets are replaced entirely.

---

## Style and formatting

### Formatter

**nixfmt** (RFC 166): the official Nix formatter. Not alejandra.

```bash
nixfmt file.nix          # Format
nixfmt --check file.nix  # Check without modifying
```

### Naming conventions

| Context | Convention | Example |
|---------|-----------|---------|
| Files | `kebab-case.nix` | `desktop-gnome.nix`, `service-config.nix` |
| Attribute names | `camelCase` | `buildInputs`, `shellHook`, `defaultPackage` |
| NixOS options | `dot.separated.camelCase` | `services.myapp.enable` |
| Variables | `camelCase` | `craneLib`, `rustToolchain` |
| Flake outputs | Follow schema exactly | `packages`, `nixosConfigurations`, `devShells` |

### Indentation

Two spaces. No tabs.

### Comments

```nix
# Single-line comment

/* Multi-line comment
   spanning multiple lines */
```

Comments explain **why**, not what. Same philosophy as all other standards.

### String style

- Short strings: double quotes `"hello world"`
- Multi-line: double single quotes `''...''` (trims leading whitespace)
- Always quote URLs (RFC 45). No bare URL syntax.

---

## Flake structure

Every flake has three top-level attributes: `description`, `inputs`, `outputs`.

### Input conventions

- Pin nixpkgs to a specific branch
- **Always use `.follows`** for transitive nixpkgs dependencies
- Without `.follows`, different inputs pull different nixpkgs versions, breaking reproducibility

### Output schema

System-specific outputs go under `packages.<system>`, `devShells.<system>`, `checks.<system>`. System-independent outputs (`nixosConfigurations`, `nixosModules`, `overlays`) go at the top level.

### Multi-system pattern

Use `lib.genAttrs` or `flake-utils.lib.eachDefaultSystem` to avoid repetition per architecture. Never put system-independent outputs inside `eachDefaultSystem`.

### Lock file

`flake.lock` is auto-generated and pins exact versions. **Commit it.** It IS reproducibility.

---

## Module patterns

### Module structure

```nix
{ config, lib, pkgs, ... }:

let
  cfg = config.services.myapp;
in {
  options.services.myapp = {
    enable = lib.mkEnableOption "My application";
    package = lib.mkPackageOption pkgs "myapp" { };
    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/myapp";
      description = "Directory for application data";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.myapp = {
      description = "My Application";
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/myapp serve";
        WorkingDirectory = cfg.dataDir;
        DynamicUser = true;
        Restart = "on-failure";
      };
    };
  };
}
```

### Key patterns

- **`cfg` alias**: Always alias `config.services.myapp` at the top of the module
- **`mkIf` + `mkMerge`**: Conditional blocks for feature toggling
- **Module composition**: Split config into logical files, use `imports` to compose

### Key module functions

| Function | Priority | Purpose |
|----------|----------|---------|
| `lib.mkDefault` | 1000 | Set default value (overridable) |
| `lib.mkForce` | 50 | Force a value |
| `lib.mkIf cond { ... }` | | Conditional config |
| `lib.mkMerge [ ... ]` | | Merge multiple config fragments |
| `lib.mkEnableOption "desc"` | | Boolean option with default `false` |
| `lib.mkPackageOption pkgs "name" {}` | | Package option with default from pkgs |

---

## Derivation and packaging

### Rust with crane

Crane is the preferred Rust packaging framework for Nix. It splits builds into dependency and source phases for maximum caching.

- Two-phase build: `buildDepsOnly` (cached) then `buildPackage` (reuses artifacts)
- `cleanCargoSource` filters source to only Rust-relevant files
- `commonArgs` pattern: share args between dep and full builds

| Option | Verdict | Reason |
|--------|---------|--------|
| `crane` | Use this | Two-phase build, best caching, actively maintained |
| `buildRustPackage` (nixpkgs) | Avoid | Single-phase, rebuilds deps on every source change |
| `naersk` | Avoid | Less composable, smaller community |

### Development shell

```nix
devShells.default = pkgs.mkShell {
  inputsFrom = [ myPackage ];  # Inherit build deps
  packages = with pkgs; [
    rust-analyzer
    cargo-nextest
    nixfmt
  ];
};
```

---

## Anti-patterns

### `rec { ... }`: avoid recursive attrsets

Use `let ... in` instead. `rec` creates easy infinite recursion by shadowing.

### `with` at file scope: pollutes namespace

Use explicit `pkgs.X` prefixing. `with` is acceptable only in small list contexts where scope is obvious.

### Lookup paths (`<nixpkgs>`): non-reproducible

Depends on `$NIX_PATH` environment variable. Pin via flake input instead.

### Unpinned `import nixpkgs {}`

Always set `config = {}; overlays = [];` explicitly. System files can influence the result otherwise.

### Shallow merge surprise with `//`

Nested attrsets are replaced entirely. Use `lib.recursiveUpdate` for deep merges.

### Bare uRLs

```nix
# Bad (deprecated syntax)
inputs.nixpkgs.url = https://github.com/NixOS/nixpkgs;

# Good
inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
```

### FHS assumptions

NixOS does not follow the Filesystem Hierarchy Standard. No `/usr/bin/`, no global `/lib/`. Use `buildFHSEnv` to wrap non-Nix binaries.

### System-independent outputs inside `eachDefaultSystem`

```nix
# Bad: nixosModules ends up under a system key
flake-utils.lib.eachDefaultSystem (system: {
  nixosModules.default = ...;  # Wrong!
});

# Good: merge system-specific and system-independent separately
flake-utils.lib.eachDefaultSystem (system: {
  packages.default = ...;
}) // {
  nixosModules.default = ...;  # Top level
}
```

---

## Conventions

1. **One flake.** Everything flows from `flake.nix`. No channel-based config, no `NIX_PATH`.
2. **Commit `flake.lock`.** It IS reproducibility.
3. **`.follows` on all transitive nixpkgs.** No version divergence.
4. **`config = {}; overlays = [];`** when importing nixpkgs. No impure system state.
5. **Crane for Rust.** Two-phase build. Always split deps from source.
6. **nixfmt for formatting.** No debate. Run in CI.
7. **Explicit > implicit.** `pkgs.git` over `with pkgs; [ git ]`.
8. **`let ... in` over `rec`.** Always.
9. **`specialArgs`** to pass flake inputs to modules. Not `_module.args`.
10. **Checks gate CI.** `nix flake check` must pass.
11. **No lookup paths.** No `<nixpkgs>`. No `$NIX_PATH` dependencies.

---

## Tooling

| Tool | Purpose |
|------|---------|
| `nix` | Package manager + language evaluator |
| `nixfmt` | Official formatter (RFC 166) |
| `nix repl` | Interactive REPL for testing expressions |
| `nix flake check` | Validate flake schema + run checks |
| `nix flake show` | Display flake outputs |
| `nixd` or `nil` | LSP for editor integration |
| `statix` | Nix linter (catches anti-patterns) |
| `deadnix` | Find unused code in Nix files |
| `nix-tree` | Visualize dependency tree |
