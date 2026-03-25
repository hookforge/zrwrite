# Mach-O arm64 Relocation Status

This document tracks the payload-mini-linker status for Mach-O/AArch64 object
relocations.

It is intentionally practical:

- which relocation families `clang` / `zig` actually emit for patch payloads
- which ones `zrwrite` already supports
- which ones are still blocked specifically by PIE / slide safety
- which ones need deeper runtime work instead of just "one more encoder"

For a reproducible local survey, run:

```bash
bash scripts/collect_macho_reloc_baseline.sh
```

That script writes its scratch objects and `otool -rv` dumps into:

```text
../ar-test/macho-reloc-baseline
```

## Supported today

`zrwrite` currently applies these Mach-O arm64 payload relocations:

- `ARM64_RELOC_UNSIGNED`
  - non-PIE absolute-pointer use cases work directly
  - PIE targets now support writable 64-bit pointer cells via a one-time
    runtime `load_bias` fixup
  - slide-sensitive absolute cells that would live in the primary/RX payload
    image are still rejected with an explicit diagnostic
- `ARM64_RELOC_BRANCH26`
- `ARM64_RELOC_PAGE21`
- `ARM64_RELOC_PAGEOFF12`
  - scale is recovered from the consumer instruction
  - current decoder covers `add (immediate)` plus common unsigned
    load/store forms, including Q-register unsigned SIMD/FP accesses
- `ARM64_RELOC_GOT_LOAD_PAGE21`
- `ARM64_RELOC_GOT_LOAD_PAGEOFF12`
  - the linker now materializes framework-owned synthetic GOT slots inside the
    writable payload image
  - payload entry wrappers run a one-time writable fixup pass that rebases
    those slots from linked addresses plus the live `load_bias`, which keeps
    Zig `extern var` loads PIE-safe on macOS arm64

## Real families observed in current baseline samples

The current sample corpus consistently produces:

- `ARM64_RELOC_PAGE21`
- `ARM64_RELOC_PAGEOFF12`
- `ARM64_RELOC_BRANCH26`
- `ARM64_RELOC_UNSIGNED`
- `ARM64_RELOC_GOT_LOAD_PAGE21`
- `ARM64_RELOC_GOT_LOAD_PAGEOFF12`
- `ARM64_RELOC_SUBTRACTOR`

`otool -rv` prints several of these in abbreviated form:

- `PAGOF12` -> `ARM64_RELOC_PAGEOFF12`
- `GOTLDP` -> `ARM64_RELOC_GOT_LOAD_PAGE21`
- `GOTLDPOFFalse` -> `ARM64_RELOC_GOT_LOAD_PAGEOFF12`
- `UNSIGND` -> `ARM64_RELOC_UNSIGNED`
- `SUB` -> `ARM64_RELOC_SUBTRACTOR`

The most important practical observation is:

- Zig `extern var` loads on Mach-O arm64 currently lower to
  `GOT_LOAD_PAGE21 + GOT_LOAD_PAGEOFF12`
- this is the Mach-O analogue of the ELF synthetic-GOT path already handled in
  the Linux backend

## Immediate gaps

### 1. Absolute pointers that land in the primary/RX payload image

Current status:

- writable 64-bit `ARM64_RELOC_UNSIGNED` cells are now supported in PIE
- read-only / primary-image absolute cells are still rejected in PIE because
  the runtime cannot safely mutate them after code signing

Why this matters:

- normal C/Zig payloads often create pointer tables, slice descriptors, or
  other data-in-data references
- writable ones now have that runtime fixup path
- primary-image ones still need a different design, such as a synthetic
  indirection cell or a stronger payload-image rebase model

Why the new writable path is still intentionally limited:

- the runtime performs a one-time guarded rebase pass and then stops touching
  payload state
- that preserves user mutations after initialization
- it still does not solve absolute cells embedded in the RX payload image

### 2. TLV / GOT pointer / subtractor-family completeness

Current status:

- `POINTER_TO_GOT`
- `TLVP_LOAD_PAGE21`
- `TLVP_LOAD_PAGEOFF12`
- `SUBTRACTOR`

are not implemented as payload-runtime-safe relocation families yet.

Not all of these are equally urgent:

- TLV/TLVP is a separate TLS story and should stay explicitly out of scope for
  now
- subtractor support is useful, but should be added only once the linker has a
  clearer PIE/rebase model for Mach-O data fixups

## Recommended implementation order

1. Preserve and improve detailed diagnostics for unsupported Mach-O relocation
   failures so real samples immediately tell us which family is blocking them.
2. Keep the relocation baseline corpus reproducible.
3. Extend the runtime-fixup model to more Mach-O relocation families that can
   safely lower to writable one-time rebasing.
4. Add selected subtractor/paired-relocation handling once the data-fixup model
   is broader.

## Current policy

Current policy:

- support relocations that remain correct under slide without extra runtime
  mutation
- support framework-owned writable fixups when the runtime semantics are clear
- reject remaining slide-sensitive families with explicit diagnostics
- avoid pretending that a structurally linked payload is safe when codesign or
  runtime would still be wrong
