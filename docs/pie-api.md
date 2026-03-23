# zrwrite PIE / ASLR Payload API

## Goal

Payload authors should be able to reason about stripped binaries with a stable
address helper API instead of manually re-implementing image-slide math.

## Public SDK pieces

### `HookRuntimeInfo`

`HookContext` now includes:

```zig
pub const HookRuntimeInfo = extern struct {
    abi_version: u16,
    flags: u16,
    reserved0: u32,
    load_bias: i64,
    site_linked_address: u64,
    site_runtime_address: u64,
};
```

### `TargetImage`

Payloads should obtain an image helper through:

```zig
const img = ctx.target();
```

Current helper methods:

- `img.loadBias()`
- `img.siteLinked()`
- `img.siteRuntime()`
- `img.resolveLinked(linked_addr)`
- `img.toLinked(runtime_addr)`
- `img.ptr(T, linked_addr)`
- `img.ptrConst(T, linked_addr)`
- `img.fnPtr(F, linked_addr)`

## Recommended payload style

Keep recovered target addresses in linked/static form:

```zig
pub const addrs = struct {
    pub const next_word = 0x10b64;
    pub const table = 0x494;
};
```

Then resolve them through the helper:

```zig
const zrwrite = @import("zrwrite");

export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    _ = address;

    const img = ctx.target();
    const table = img.ptrConst([256]u32, addrs.table);
    _ = table;
}
```

## Important distinction

These are already runtime addresses and should generally be used directly:

- `ctx.regs.named.x0 ... x30`
- `ctx.sp`
- `ctx.pc`
- pointers read from target memory

These should be resolved through `ctx.target()`:

- addresses copied from IDA/Ghidra/objdump
- hardcoded internal target addresses
- recovered function/data VAs in stripped binaries

## Current implementation status

This API file fixes the payload-facing surface first.

Today:

- the helper types are public
- the Linux/AArch64 instrument bridge computes runtime image metadata for the
  validated PIE instrument path
- ET_EXEC / non-PIE naturally behaves as a zero-bias case

Still pending:

- PIE-safe coverage for every long-detour fallback path
- ET_DYN relocation policy tightening in the payload mini-linker
