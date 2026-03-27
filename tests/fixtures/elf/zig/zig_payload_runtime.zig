const c = @cImport({
    @cInclude("zrwrite_sdk.h");
});

// Export the backing objects so the optimizer must keep them as proper
// sections/symbols. That gives the mini-linker a realistic Zig payload to lay
// out and relocate across `.rodata`, `.data`, and `.bss`.
export const table = [_]u64{ 1, 2, 3 };
export var table_ptr: [*]const u64 = &table;
export var mutable_state: u64 = 0x40;
export var scratch: [16]u8 = undefined;

noinline fn helper() u64 {
    return table_ptr[1] + mutable_state + scratch[0];
}

export fn on_hit(address: u64, ctx: *c.zrwrite_hook_context_t) callconv(.c) void {
    _ = address;
    scratch[0] = 5;
    mutable_state +%= 1;
    ctx.regs.x[0] = helper();
}
