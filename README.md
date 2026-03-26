# ZRWRITE

`zrwrite` is a static binary patching framework focused on AArch64 targets.

Today it targets:

- Linux ELF64
- macOS thin Mach-O arm64

The main use case is: you have a stripped or optimized binary, you know a
useful patch site, and you want to inject new logic without rebuilding the
original program.

## What zrwrite does

`zrwrite` currently supports two main hook styles:

- `replace`
- `instrument`

`replace` is for full detours:

- replace a function entry
- force a return value
- redirect execution into a new implementation

`instrument` is for patch-site logic injection:

- log or inspect registers
- modify arguments or return values
- early-return by editing `ctx.pc`
- instrument interior instructions inside large optimized functions

The design goal is deliberately low-level:

- `zrwrite` guarantees architectural control over registers / PC / SP /
  replayed instructions
- language ABI meaning is owned by the payload author

If you patch an Objective-C, C++, Rust, Swift, or custom ABI boundary, you must
write the payload with the correct calling convention and runtime layout in
mind.

## Supported target model

Current public scope:

- AArch64 only
- static patching, not runtime injection
- Zig-authored payload objects are the primary path
- C payload objects can also work when they stay within the supported payload
  model
- payload sections:
  - `.text`
  - `.rodata`
  - `.data`
  - `.bss`

Explicitly not a goal right now:

- "arbitrary normal Zig executable" support inside payloads
- TLS-heavy payload code
- full C++ exception / unwind interoperability
- fat / universal Mach-O handling
- iOS / arm64e / PAC-specific support

## Basic workflow

The normal workflow has three steps:

1. Write a payload and build it into an object file.
2. Describe the hook(s) in a meta JSON or pass them through CLI flags.
3. Build a `.zrpb` bundle and apply it to the target binary.

Typical commands:

```bash
zig build-obj -target aarch64-macos -O ReleaseSmall -fstrip \
  -Mroot=payload.zig \
  -femit-bin=payload.o

zrwrite bundle --output patch.zrpb --meta hook.meta.json

zrwrite apply --bundle patch.zrpb --input target.bin --output target.patched
```

On macOS you must ad-hoc sign the patched output before running it:

```bash
codesign -f -s - target.patched
```

## Meta JSON format

The human-authored meta JSON format is:

```json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload": {
    "object_path": "payload.o",
    "object_format": "macho"
  },
  "hooks": [
    {
      "kind": "instrument",
      "target": {
        "kind": "virtual_address",
        "virtual_address": "0x1000038bc"
      },
      "expected_bytes": "4810001208150011",
      "handler_symbol": "on_hit"
    }
  ]
}
```

Important details:

- `payload.object_path` is resolved relative to the meta file path
- the meta file does not name the target binary
- it only describes how to build the bundle and where the hook should land
- one meta file can describe multiple hooks

Hook targets can currently be located by:

- symbol
- linked virtual address
- file offset
- exact byte pattern plus optional offset

## How to choose a hook style

Use `replace` when:

- you want a different implementation
- you want to intercept a clean function entry
- you do not need to preserve the original body

Use `instrument` when:

- the original function is too large or inlined
- you only want to tweak state at a specific instruction
- you want to log, gate, or rewrite control flow locally

`instrument` is the more important mode for stripped / optimized binaries.

## Replace example

Suppose the original Objective-C method is:

```objc
- (const char *)fetchBodyCString;
```

You can replace it with a Zig payload that matches the AArch64 C ABI view of
that method:

```zig
const hooked = "[artest] hooked.";

export fn replacement_fetchBodyCString(
    self: ?*anyopaque,
    cmd: ?*anyopaque,
) callconv(.c) [*:0]const u8 {
    _ = self;
    _ = cmd;
    return hooked.ptr;
}
```

Matching meta JSON:

```json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload": {
    "object_path": "payload_replace.o",
    "object_format": "macho"
  },
  "hooks": [
    {
      "kind": "replace",
      "target": {
        "kind": "symbol",
        "symbol": "-[ArHttpClient fetchBodyCString]"
      },
      "handler_symbol": "replacement_fetchBodyCString"
    }
  ]
}
```

## Instrument example

You can achieve an early return entirely at the register / PC layer:

```zig
const zrwrite = @import("zrwrite");

const hooked = "[artest] hooked.";

export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    _ = address;

    // Objective-C method call ABI on AArch64:
    // x0 = self
    // x1 = _cmd
    // x30 = caller return address
    _ = ctx.regs.named.x0;
    _ = ctx.regs.named.x1;

    ctx.regs.named.x0 = @intFromPtr(hooked.ptr);
    ctx.pc = ctx.regs.named.x30;
}
```

Matching meta JSON:

```json
{
  "target": {
    "arch": "aarch64",
    "os": "macos",
    "binary_format": "macho"
  },
  "payload": {
    "object_path": "payload_instrument.o",
    "object_format": "macho"
  },
  "hooks": [
    {
      "kind": "instrument",
      "target": {
        "kind": "virtual_address",
        "virtual_address": "0x100000d50"
      },
      "expected_bytes": "680a00f9",
      "handler_symbol": "on_hit"
    }
  ]
}
```

## Why `expected_bytes` matters

`expected_bytes` is strongly recommended for any real patch.

It is the first safety guard against:

- binary version drift
- compiler changes
- wrong IDA address recovery
- accidental patching of the wrong build

If the bytes at the target location do not match, `zrwrite` fails closed
instead of silently patching the wrong code.

Use `inspect` to recover a stable hook snippet:

```bash
zrwrite inspect \
  --input target.bin \
  --symbol some_symbol
```

Or:

```bash
zrwrite inspect \
  --input target.bin \
  --vaddr 0x100000d50
```

`inspect` prints:

- linked virtual address
- file offset
- recommended `expected_bytes`
- an exact pattern snippet you can paste into meta JSON for stripped binaries

## Internal execution model

At a high level, `instrument` works like this:

1. Resolve the hook site from symbol / vaddr / file offset / pattern.
2. Validate the bytes at that site.
3. Determine how many instructions must be stolen from the original binary.
4. Build a bridge / trampoline path.
5. Inject the payload object and relocate its code/data.
6. Redirect execution at the patch site into the bridge.
7. Save architectural state into `HookContext`.
8. Call your payload callback.
9. Resume according to the selected hook mode.

That resume step is the hard part.

If an overwritten instruction is safe to replay in a raw trampoline, `zrwrite`
can execute it out-of-line. If it is PC-relative or otherwise relocation
sensitive, the patcher must either:

- apply an explicit semantic replay strategy, or
- reject the patch

The core rule is: if `zrwrite` cannot prove the rewritten control flow is safe,
it should fail closed.

## Widened windows and multi-instruction steal

For interior instrumentation, one instruction is not always enough.

`stolen_instruction_count` tells `zrwrite` to steal a wider patch window. This
is useful when:

- the hook site must be widened to install a long detour
- the displaced sequence must be replayed as a small group
- you are instrumenting inside a large optimized / inlined function

This is not "copy arbitrary bytes and hope".

Wide windows only work when `zrwrite` can prove the displaced instructions are
handled correctly. Otherwise the patch is rejected.

Two important consequences:

- incoming branches into the middle of the stolen window are a special case
- PC-relative instructions require explicit replay support

If you care about the exact replay policy, read
[`docs/replay-policy.md`](docs/replay-policy.md).

## Address model: linked vs runtime addresses

One of the easiest ways to write a wrong payload is mixing file offsets,
linked addresses, and runtime pointers.

`zrwrite` uses three address domains:

- file offset
- linked virtual address
- runtime virtual address

Payload rule:

- register values, `ctx.pc`, `ctx.sp`, and pointers read from target memory are
  already runtime addresses
- addresses copied from IDA / Ghidra / `objdump` should be treated as linked
  addresses

For PIE / ASLR-safe payload code, resolve recovered linked addresses through
`ctx.target()`:

```zig
const img = ctx.target();
const fn_ptr = img.fnPtr(*const fn () callconv(.c) void, 0x100012340);
```

Do not manually scatter `+ load_bias` math across payload code.

Read:

- [`docs/address-model.md`](docs/address-model.md)
- [`docs/pie-api.md`](docs/pie-api.md)

## HookContext and payload ABI

The long-term payload callback shape is:

```zig
export fn on_hit(hit_address: u64, ctx: *zrwrite.HookContext) callconv(.c) void
```

`HookContext` is an architectural snapshot. Payloads are expected to:

- read and write GPR state
- read and write `pc`
- read and write `sp`
- reason about target image base / load bias through runtime metadata

Important design rule:

- `zrwrite` exposes architecture state
- it does not understand the source-language semantics for you

If you patch:

- Objective-C message sends
- Rust return slots
- C++ object layouts
- Swift reference semantics

you must recover and respect that ABI yourself.

## Shared payload state

Within one rewrite session, repeated `instrument` hooks that point at the same
payload object behave like different exported functions from one injected
payload module.

That means:

- payload `.text` is injected once
- payload `.data` / `.bss` are shared across those handlers
- payload globals are shared between those instrument callbacks

This is the user-facing "looks like one payload" model.

This shared-state guarantee should currently be read as an `instrument`-hook
rule. Do not assume `replace` hooks share runtime payload state in exactly the
same way.

## `zrstd` and payload authoring constraints

A patch payload is not a normal hosted Zig executable.

That is why `zrwrite` ships `zrstd`: a small payload-side helper layer for
things like:

- printing
- bounded formatting
- fixed-buffer assembly
- explicit byte copy / move / fill helpers

Use `zrstd` when possible instead of assuming `std.debug.print` or a large
stdlib path is safe for payload code.

Current payload authoring rules:

- prefer explicit, boring code
- avoid hidden runtime dependencies
- avoid TLS-heavy features
- avoid assuming libc or a process runtime exists just because the target
  program links one

Read:

- [`docs/zrstd.md`](docs/zrstd.md)

## Important user-side caveats

These are the main things users should know before writing serious patches.

### 1. A patch site is not a source-language boundary

If you instrument the middle of a Rust, Objective-C, or C++ function, the
register state only reflects the machine-level ABI at that instruction.

You might be seeing:

- a hidden return slot
- inlined temporaries
- compiler-owned scratch values
- register allocation artifacts

Reverse-engineering the real meaning of the site is your job.

### 2. `replace` and `instrument` are different tools

Do not use `replace` when you actually need local control-flow surgery inside a
huge optimized function. Use `instrument`.

Do not use `instrument` when a clean function-entry replacement is enough. Use
`replace`.

### 3. Prefer linked addresses in metadata

`--target-vaddr` and meta JSON virtual addresses should use the linked image
address seen in disassembly, not a runtime ASLR-shifted pointer.

### 4. Prefer `expected_bytes`

Treat `expected_bytes` as a default safety requirement, especially for:

- stripped binaries
- file-offset hooks
- pattern-derived hooks
- CI or repeatable patch pipelines

### 5. Failures are often useful

If `zrwrite` rejects a hook, that usually means it found a real correctness
problem:

- unsupported relocation family
- unsupported replay case
- multiple pattern matches
- bytes mismatch
- unsafe patch window

A hard failure is better than a subtly broken binary.

### 6. macOS runtime closure matters

On macOS, structural patch success is not enough. The final output still needs
to be codesign-clean enough for ad-hoc signing and runtime execution.

### 7. TLS is still a boundary

Payload code that implicitly pulls in TLS, thread-locals, or a large hosted
runtime surface is still outside the intended safe subset.

## Practical advice for writing payloads

If you are authoring a new payload, the safest pattern is:

1. Start with `inspect`.
2. Patch one clean site first.
3. Add `expected_bytes`.
4. Keep the payload tiny until the hook is known-good.
5. Only then start layering language-specific logic on top.

For stripped binaries:

- prefer pattern locators or linked VAs recovered from IDA
- use exact bytes as a version guard
- keep your own recovered addresses in linked form and resolve them through
  `ctx.target()`

## Testing and validation

Local validation:

```bash
zig build
zig build test
```

Linux/AArch64 runtime validation uses the Orb-hosted Ubuntu machine:

```bash
ssh ubuntu@orb
```

The current remote smoke coverage is documented in
[`docs/testing.md`](docs/testing.md).

## Further reading

- [`docs/patch-abi.md`](docs/patch-abi.md)
- [`docs/address-model.md`](docs/address-model.md)
- [`docs/pie-api.md`](docs/pie-api.md)
- [`docs/replay-policy.md`](docs/replay-policy.md)
- [`docs/zrstd.md`](docs/zrstd.md)
- [`docs/testing.md`](docs/testing.md)
- [`docs/macho-reloc-status.md`](docs/macho-reloc-status.md)
- [`docs/v1-scope.md`](docs/v1-scope.md)

## Status summary

The current project direction is:

- static AArch64 patching first
- fail-closed correctness over "best effort"
- strong support for stripped / optimized binaries
- enough payload runtime surface to write real Zig instrumentation

If you find a hook site that should be valid but currently fails, that is a
useful bug report. The intended model is not "only easy function entry hooks";
the intended model is "real interior instrumentation for difficult binaries,
with correctness checks instead of silent corruption."
