# zrstd

`zrstd` is the first payload-side helper module for `zrwrite`.

Its purpose is simple:

- give injected Zig payloads a small **supported** utility layer
- avoid encouraging users to call `std.debug.print` directly
- keep the implementation compatible with the current Linux/AArch64 static
  payload runtime boundary

## Why it exists

Today, a patched payload is **not** a normal hosted Zig executable.

That means some familiar standard-library entry points pull in more runtime than
the current payload linker/runtime can safely support. In practice, the most
common example is `std.debug.print`, which brings in TLS-heavy and broader
runtime paths that are outside the current supported envelope.

`zrstd` gives users a narrow, explicit alternative:

- formatted printing through `zrstd.debug.print(...)`
- newline helpers through `zrstd.debug.println(...)`
- raw byte output through `zrstd.writeStdout(...)` / `zrstd.writeStderr(...)`
- bounded formatting through `zrstd.formatInto(...)`
- lightweight hex helpers through `zrstd.fmt.*`
- small fixed-buffer composition through `zrstd.FixedBuffer`
- explicit slice helpers through `zrstd.mem.*`
- payload-local `memcpy` / `memmove` / `memset` shims emitted into the object

## Current support scope

`zrstd` currently targets:

- Linux
- AArch64
- statically injected payload objects

It should be treated as a payload-authoring compatibility layer, not as a full
replacement for Zig stdlib facilities.

## Example

In an external payload project:

```zig
const zrwrite = @import("zrwrite");
const zrstd = @import("zrstd");

export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    zrstd.debug.print("hook @0x{x} x0=0x{x}\n", .{
        address,
        ctx.regs.named.x0,
    });
}
```

And in `build.zig`:

```zig
const zrwrite_dep = b.dependency("zrwrite", .{});
payload_mod.addImport("zrwrite", zrwrite_dep.module("zrwrite"));
payload_mod.addImport("zrstd", zrwrite_dep.module("zrstd"));
```

## Design rule

If a helper is likely to pull in:

- TLS
- allocator requirements
- libc process/runtime assumptions
- exception/unwind expectations

then it should **not** quietly appear in `zrstd`.

`zrstd` should stay small, boring, and explicitly validated.
