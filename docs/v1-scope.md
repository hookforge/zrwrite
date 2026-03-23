# zrwrite v1 Scope

## Supported in v1

### Architecture

- AArch64 only

### Binary formats

- Linux ELF64
- macOS thin Mach-O arm64

### Hook styles

- `replace`
- `instrument`
- `wrap`

### Payload authoring

- Zig-authored patch code
- `zrstd` payload helper subset for printing / formatting
- object-file based payload ingestion
- payload sections:
  - `.text`
  - `.rodata`
  - `.data`
  - `.bss`

### Runtime ABI

- stable `HookContext`
- stable callback signature
- general-purpose register access
- program counter / stack pointer / NZCV access
- FP/SIMD state planned as part of the stable ABI surface

## Explicitly Out of Scope for v1

- x86_64
- iOS / arm64e / PAC-specific support
- fat / universal Mach-O binaries
- full dynamic import injection
- TLS-heavy payload support
- C++ exceptions / unwind interoperability guarantees
- "arbitrary Zig program" support without authoring constraints

## Release Gates

v1 should not be called complete until all of the following are true:

1. Linux ELF AArch64 can inject and execute a non-trivial Zig payload
2. PIE binaries are supported on Linux
3. Common AArch64 PC-relative instructions are handled through explicit replay
   policy rather than accidental success
4. macOS arm64 thin executables can be patched and re-signed for execution
5. There is a documented runtime validation path using `ssh ubuntu@orb`

## Working Assumptions

- Fail closed is better than emitting a broken binary
- The first shipping release should optimize for correctness and debuggability,
  not maximum opcode or relocation coverage
- Support claims must be backed by automated fixtures or remote smoke tests
