# Fixture layout

- `shared/`: cross-platform smoke payloads and tiny host programs reused by multiple suites
- `elf/payload/`: payload-linker / relocation demo fixtures used by helper scripts
- `elf/replay/`: AArch64 replay / widened-window / resume / detour fixtures
- `elf/zig/`: Zig payload integration fixtures for ELF tests
- `macho/layout/`: Mach-O layout / LINKEDIT / ObjC / pointer-diagnostic fixtures
- `macho/shared/`: Mach-O inputs reused by both layout and runtime suites
- `macho/runtime/`: Mach-O runtime / codesign / dylib-style payload fixtures

Legacy `condbr_*` and `tstbr_*` files were moved under `elf/payload/` because
they are currently used by demo scripts rather than the main test suites.
