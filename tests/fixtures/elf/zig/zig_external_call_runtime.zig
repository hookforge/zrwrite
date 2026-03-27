const c = @cImport({
    @cInclude("zrwrite_sdk.h");
});

extern fn target_helper(x: u64) callconv(.c) u64;

// The pointer itself lives in `.data` and is initialized through an `ABS64`
// relocation against an undefined symbol that must be resolved from the target
// ELF image. `helper()` then exercises both:
// - a direct `CALL26` relocation to `target_helper`
// - an indirect call through the relocated `.data` function pointer
export var target_helper_ptr: *const fn (u64) callconv(.c) u64 = target_helper;

noinline fn helper() u64 {
    return target_helper(7) + target_helper_ptr(8);
}

export fn on_hit(address: u64, ctx: *c.zrwrite_hook_context_t) callconv(.c) void {
    _ = address;
    ctx.regs.x[0] = helper();
}
