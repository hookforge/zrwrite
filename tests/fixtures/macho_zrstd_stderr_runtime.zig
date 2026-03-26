const zrwrite = @import("zrwrite");
const zrstd = @import("zrstd");

var g_hits: usize = 0;

// Exercise the Darwin payload-side stderr path with a mix of:
// - writable payload state (`g_hits`)
// - `{s}` string formatting
// - default integer/bool formatting
//
// This is intentionally closer to the real ImHex payload than the older
// stdout-only zrstd smoke.
export fn on_hit(address: u64, ctx: *zrwrite.HookContext) callconv(.c) void {
    _ = address;
    g_hits += 1;
    zrstd.debug.eprintln(
        "stderr hit={} stage={s} ok={}",
        .{ g_hits, "darwin", true },
    );
    ctx.regs.named.x0 += 9;
}
