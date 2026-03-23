# zrwrite Testing Notes

## Local Validation

Use local validation for:

- unit tests
- bundle parsing tests
- ELF metadata regression tests
- replay planner tests

Typical commands:

```bash
zig build test
zig build
```

## Remote Linux/AArch64 Validation

Use the Orb-hosted Ubuntu AArch64 machine for Linux runtime smoke tests:

```bash
ssh ubuntu@orb
```

The current environment confirms:

- host architecture: `aarch64`
- operating system: Ubuntu Linux

## Why Remote Validation Matters

Local macOS development can prove that we generate syntactically valid bytes,
but it cannot prove that a patched Linux AArch64 executable actually runs with
the expected ABI and control-flow behavior.

That means any milestone that changes one of the following must leave behind a
remote smoke path:

- instrument stub code generation
- branch/trampoline behavior
- payload relocation
- ELF image layout

## Current Constraint

The remote machine currently does not have `zig` preinstalled, so tests that
need Zig must either:

- upload already-built artifacts, or
- bootstrap/install Zig as part of the remote workflow

For the near term, prefer uploading locally built artifacts for runtime smoke
validation.

Useful remote smoke scripts:

```bash
bash scripts/orb_encrypt_replace_demo.sh
bash scripts/orb_semantic_instrument_demo.sh
bash scripts/orb_condbr_demo.sh
bash scripts/orb_long_detour_demo.sh
bash scripts/orb_tstbr_demo.sh
bash scripts/orb_x16_resume_demo.sh
bash scripts/orb_x17_resume_demo.sh
bash scripts/orb_wide_window_demo.sh
bash scripts/orb_zig_payload_demo.sh
bash scripts/orb_zig_composite_demo.sh
bash scripts/orb_zig_external_call_demo.sh
bash scripts/orb_zig_external_data_demo.sh
```

`orb_x16_resume_demo.sh` is the dedicated runtime regression for the resume
bridge closure: it proves that a callback write to `ctx.regs.x16` survives both
the bridge restore path and the raw trampoline path on a real Linux/AArch64
machine.

`orb_x17_resume_demo.sh` covers the new direct-resume fast path: it proves that
when the callback leaves `ctx.sp` / `ctx.pc` on the bridge-owned replay path, a
callback write to `ctx.regs.x17` now also survives back into live execution
state on real Linux/AArch64 hardware.

`orb_wide_window_demo.sh` is the first widened patch-window smoke. It validates
that `zrwrite` can steal and replay a 4-instruction straight-line window, patch
the extra overwritten instructions with `nop`, and still resume correctly on
real Linux/AArch64 hardware.

`orb_long_detour_demo.sh` is the widened-window range-escape smoke. It forces
the injected bridge more than ±128 MiB away from the hook site and validates
that `zrwrite` falls back to a 16-byte PIE-safe long detour (`adrp/add/br/nop`)
at the patch site while still replaying the stolen instructions correctly on
Orb.

`orb_condbr_demo.sh` is the dedicated runtime smoke for
`R_AARCH64_CONDBR19`. It proves that a payload whose callback contains a
cross-section conditional branch relocation still links, patches, and resumes
correctly on real Linux/AArch64 hardware.

`orb_tstbr_demo.sh` is the corresponding runtime smoke for
`R_AARCH64_TSTBR14`. It validates the `tbz` / `tbnz` style relocation family in
an end-to-end patched executable on Orb.

`orb_zig_payload_demo.sh` is the first end-to-end ELF/AArch64 mini-linker smoke
for a real Zig-authored payload object. It exercises `.rodata`, `.data`, `.bss`
layout plus relocation fixups before validating runtime behavior on Orb.

`orb_zig_composite_demo.sh` is the broader end-to-end composite regression: the
payload reads an external data symbol, writes payload-local `.bss`, and then
calls an external target function before resuming. This is the current
high-value runtime proof that the ELF/AArch64 mini-linker can compose multiple
symbol-resolution modes in one real Zig payload.

`orb_zig_external_call_demo.sh` extends that coverage to undefined-symbol
resolution against the target ELF image itself, including a direct `CALL26`
relocation and a relocated function pointer stored in payload `.data`.

`orb_zig_external_data_demo.sh` extends the undefined-symbol coverage to Zig
`extern var` data accesses. That path now exercises synthetic payload-local GOT
slots plus `ADR_GOT_PAGE` / `LD64_GOT_LO12_NC` relocations before validating
real Linux/AArch64 runtime behavior on Orb.
