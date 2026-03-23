# zrwrite Replay Policy

## Why Replay Policy Exists

Static instrumentation works by displacing one instruction and redirecting
control flow into an out-of-line helper. That only stays correct when the
displaced instruction is safe to execute away from its original address.

Many AArch64 instructions are fine in a raw trampoline. Common PC-relative
instructions are not.

## Core Rule

Every displaced instruction must fall into one of these buckets:

1. **Raw trampoline safe**
   - copy the opcode into a trampoline and execute it there
2. **Semantic replay supported**
   - do not execute the original bytes in the trampoline
   - instead reproduce the architectural effect explicitly
3. **Unsupported**
   - fail closed at patch time

## Initial Whitelist for Semantic Replay

The first replay planner milestone targets these AArch64 instruction families:

- `adr`
- `adrp`
- `ldr (literal)` into `wN`
- `ldr (literal)` into `xN`
- `ldr (literal)` into `sN`
- `ldr (literal)` into `dN`
- `ldr (literal)` into `qN`
- `ldrsw (literal)`
- `prfm (literal)`
- `b`
- `bl`
- `b.cond`
- `cbz` / `cbnz`
- `tbz` / `tbnz`

## Non-Negotiable Safety Rule

If `zrwrite` cannot prove a safe replay strategy, it must reject the patch.

Unsupported instructions must never silently fall back to:

- executing relocated bytes with different semantics
- truncating state restoration
- "best effort" control-flow recovery

## Relationship to the Current Rewriter

Today the rewriter only supports bucket (1): raw-trampoline-safe instructions.
The new replay planner introduces bucket (2) as explicit metadata, but the
current static patcher still rejects those plans until the injected runtime
bridge can apply them correctly.

That staged rollout is intentional: planning first, runtime use second.
