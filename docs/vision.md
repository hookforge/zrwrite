# zrwrite Vision

## Mission

`zrwrite` should become a static binary patching framework for **AArch64**
executables where patch logic is authored in **Zig** and then injected into
existing Linux ELF or macOS Mach-O binaries.

The intended end state is not just "append some bytes and branch there". The
tooling should be strong enough to support:

- function replacement
- function entry wrapping
- instruction-level instrumentation
- logic augmentation around existing control flow
- stable callback/runtime ABI for Zig-authored payloads

## Product Shape

`zrwrite` should evolve into four cooperating layers:

1. **ISA layer** for AArch64 decoding, replay analysis, and code emission
2. **Mini-linker layer** that can load Zig/Clang object files and apply the
   subset of relocations needed by real patch payloads
3. **Image backend layer** for ELF and Mach-O rewriting
4. **Authoring/runtime layer** that exposes a stable patch ABI and a usable Zig
   build workflow

## v1 Principles

- Focus on **AArch64 only**
- Deliver **Linux ELF first**, then **macOS Mach-O**
- Fail closed on unsupported opcodes or relocations
- Prefer small, explicit support matrices over fuzzy "maybe works" claims
- Keep the public patch ABI stable even when the internal runtime changes

## Validation Requirement

Local unit tests are necessary but not sufficient. Every meaningful phase
should leave behind a validation path that can be exercised on the remote
Ubuntu AArch64 host available through:

```bash
ssh ubuntu@orb
```

That host is the primary runtime validation target for Linux/AArch64 behavior.
