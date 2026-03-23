const zrwrite = @import("zrwrite");
const zrstd = @import("zrstd");

// This fixture intentionally exercises the public authoring workflow for real
// users:
// - `@import("zrwrite")` for the stable HookContext ABI
// - `@import("zrstd")` for payload-safe formatted output
//
// It also keeps `.rodata`, `.data`, and `.bss` alive so the payload still
// travels through the mini-linker paths used by richer Zig payloads.
export const table = [_]u64{ 1, 2, 3 };
export var mutable_state: u64 = 40;
export var scratch: [16]u8 = undefined;

noinline fn helper() u64 {
    scratch[0] = 30;
    return table[1] + mutable_state + scratch[0];
}

export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    zrstd.debug.print("zrstd helper hit @0x{x}\n", .{address});
    ctx.regs.x[0] = helper();
}
