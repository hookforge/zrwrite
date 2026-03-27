const c = @cImport({
    @cInclude("zrwrite_sdk.h");
});

extern var target_value: u64;

// Zig currently lowers `extern var` accesses through GOT-style relocations on
// AArch64 even for our static ET_REL payload objects. The mini-linker must
// therefore synthesize a local pointer slot, relocate the `adrp/ldr` pair to
// that slot, and seed the slot with the final target-side symbol address.
export fn on_hit(address: u64, ctx: *c.zrwrite_hook_context_t) callconv(.c) void {
    _ = address;
    ctx.regs.x[0] = target_value + 1;
}
