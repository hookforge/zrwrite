const c = @cImport({
    @cInclude("zrwrite_sdk.h");
});

extern fn target_helper(x: u64) callconv(.c) u64;
extern var target_value: u64;

// Keep this truly uninitialized so Zig places it into `.bss`. The regression
// then proves that the mini-linker can still relocate and access it after
// reading an external data symbol and calling back into an external target
// function.
export var scratch: u64 = undefined;

noinline fn helper() u64 {
    scratch = target_value + 2;
    return target_helper(scratch);
}

export fn on_hit(address: u64, ctx: *c.zrwrite_hook_context_t) callconv(.c) void {
    _ = address;
    ctx.regs.x[0] = helper();
}
