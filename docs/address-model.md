# zrwrite Address Model

## Why this document exists

Static patching and runtime instrumentation both talk about "addresses", but a
rewriter can only stay correct when it keeps different address domains
explicit.

`zrwrite` distinguishes three address forms:

1. **file offset**
2. **linked virtual address**
3. **runtime virtual address**

That separation becomes mandatory once PIE / ASLR are involved.

## 1. File offset

A file offset is a byte position inside the on-disk binary.

Examples:

- the start of an ELF `PT_LOAD`
- the patch-site byte position in the input file
- the offset where new payload bytes are inserted

File offsets are for rewrite-time mechanics only.

They are **not** runtime pointers and should not appear in payload-side memory
access logic.

## 2. Linked virtual address

A linked virtual address is the static image address recorded in the binary
headers, symbol table, or disassembly.

Examples:

- addresses shown by `objdump`
- addresses recovered from IDA / Ghidra after removing any analysis-only base
- `--target-vaddr` values in `zrwrite`

This is the stable address domain used by:

- bundle metadata
- replay planning
- payload-side hardcoded recovered target addresses

## 3. Runtime virtual address

A runtime virtual address is the live address seen by the CPU after the loader
maps the image into memory.

Examples:

- `ctx.regs.named.x0`
- `ctx.sp`
- `ctx.pc`
- real code/data pointers read from process memory

For PIE/ASLR-enabled binaries, the relationship is:

```text
runtime = linked + load_bias
```

## Payload-side rule

Payload code should treat register-derived pointers as runtime addresses.

If the payload wants to use a recovered static address from reverse
engineering, it should resolve that address through the image helper:

```zig
const img = ctx.target();
const runtime_addr = img.resolveLinked(0x10b64);
```

Or for typed access:

```zig
const table = img.ptrConst([256]u32, 0x494);
const func = img.fnPtr(*const fn () callconv(.c) void, 0x10f20);
```

That keeps ASLR math centralized instead of scattering `+ load_bias` across
payload source.

## Current rollout status

The public helper surface is now fixed around:

- `HookContext.runtime`
- `HookContext.target()`
- `TargetImage.resolveLinked(...)`
- `TargetImage.toLinked(...)`

The current Linux/AArch64 instrument bridge now populates this metadata from a
live in-stub runtime address anchor, so payload code can resolve linked/static
addresses correctly under PIE / ASLR on the validated instrument path.

Remaining PIE work still exists elsewhere in the system, especially around:

- every long-detour fallback path
- the breadth of ET_DYN payload relocation support
