const std = @import("std");
const apply = @import("../core/apply.zig");

/// Helper used by specialized patchers that embed a `.zrpb` bundle with
/// `@embedFile(...)`.
pub fn run(allocator: std.mem.Allocator, embedded_bundle: []const u8, args: []const []const u8) !void {
    if (args.len != 3) {
        std.debug.print("usage: {s} <input-binary> <output-binary>\n", .{args[0]});
        return error.InvalidArgument;
    }

    _ = try apply.applyBundleBytesToPath(allocator, embedded_bundle, args[1], args[2]);
}

pub fn mainWithEmbeddedBundle(embedded_bundle: []const u8) !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    try run(allocator, embedded_bundle, args);
}
