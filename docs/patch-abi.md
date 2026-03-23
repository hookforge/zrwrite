# zrwrite Patch ABI

## Purpose

The patch ABI is the contract between:

- the rewritten target binary
- the injected runtime bridge
- the Zig-authored payload callback

This contract must remain stable even if the internal stub layout, relocation
strategy, or bundle format changes.

## Callback Shape

The long-term callback model is:

```zig
export fn on_hit(hit_address: u64, ctx: *zrwrite.HookContext) callconv(.c) void
```

Where:

- `hit_address` is the hook-site address reported by the bridge
- `ctx` is a mutable architectural snapshot

Payloads should use:

```zig
const img = ctx.target();
```

to convert recovered linked/static image addresses into runtime pointers.

## HookContext Contract

`HookContext` represents architectural state, not implementation detail. At a
minimum it must model:

- general-purpose registers
- stack pointer
- program counter
- condition flags / CPSR subset used by replay logic
- FP/SIMD registers
- FP control/status registers
- runtime image metadata needed to reason about PIE / ASLR safely

## Control-Flow Rule

The ABI should support the following invariant:

- the callback may rewrite architectural state in `ctx`
- later runtime stages decide whether to:
  - replay the displaced instruction
  - skip it
  - return to caller
  - jump elsewhere

In other words, the callback edits state; the selected hook mode defines how
execution resumes when the callback returns.

## Compatibility Policy

- New fields may only be added if ABI layout remains compatible
- Existing field meaning must not change silently
- C and Zig declarations must stay layout-identical
- Any temporary implementation gap must be documented as an implementation
  limitation, not an ABI change

## Current Implementation Gap

The ABI shape now reserves `HookContext.runtime` as the payload-visible home
for:

- `load_bias`
- `site_linked_address`
- `site_runtime_address`

Today the Linux/AArch64 bridge initializes that block as a stable zero-bias
mapping for ET_EXEC / non-PIE and now also computes a real runtime load-bias
view for the validated Linux/AArch64 instrument PIE path.

The remaining PIE work is runtime work, not API-shape work:

- cover every long-detour fallback path with the same PIE-safe semantics
- tighten ET_DYN relocation handling

The Linux/AArch64 bridge now saves and restores:

- all GPR state from `x0` through `x30`
- `sp`
- `pc`
- `nzcv`
- the full FP/SIMD register bank
- `fpsr` / `fpcr`

The previously open `x16` resume-path bug is now closed, and the common
bridge-owned replay path now also preserves callback writes to `x17` when:

- `ctx.sp` still equals the architectural hook-site stack pointer, and
- `ctx.pc` resolves to one of the bridge-known replay targets

In that case the bridge can restore the full GPR bank and resume through a
direct branch.

One narrower implementation limitation remains: a truly dynamic resume still
needs one live branch-carrier register plus one live SP carrier. When the
callback requests an arbitrary `ctx.pc` or custom `ctx.sp`, the generic
indirect-resume path still uses `x17` for that terminal hand-off, so callback
writes to `ctx.regs.x[17]` are not guaranteed to materialize in that fallback
case. This is an implementation limitation, not an ABI change.
