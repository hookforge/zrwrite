const zrwrite = @import("zrwrite");
const zrstd = @import("zrstd");

// This fixture exists specifically to exercise a Mach-O relocation/codegen
// shape that earlier payload-linker revisions got wrong:
// `zrstd.debug.print("... {} {}", .{ a, b })` on macOS arm64 caused Zig to
// materialize a 16-byte slice descriptor constant via a Q-register PAGEOFF12
// load. If the linker decoded that consumer as byte-scaled instead of
// 16-byte-scaled, the descriptor pointed at garbage and the payload fell back
// to "<zrstd: formatted output truncated>" at runtime.
export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    _ = address;
    zrstd.debug.print("trace next_word block={} word={}\n", .{ @as(usize, 1), @as(usize, 2) });
    ctx.regs.named.x0 += 9;
}
