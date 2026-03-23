const std = @import("std");
const bundle = @import("bundle.zig");
const rewriter = @import("rewriter.zig");

pub const ApplyReport = rewriter.RewriteReport;

pub fn applyBundleFileToPath(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
    input_path: []const u8,
    output_path: []const u8,
) !ApplyReport {
    var owned_bundle = try bundle.loadFromPath(allocator, bundle_path);
    defer owned_bundle.deinit();
    return applyLoadedBundleToPath(allocator, &owned_bundle, input_path, output_path);
}

pub fn applyBundleBytesToPath(
    allocator: std.mem.Allocator,
    bundle_bytes: []const u8,
    input_path: []const u8,
    output_path: []const u8,
) !ApplyReport {
    var owned_bundle = try bundle.loadFromBytes(allocator, bundle_bytes);
    defer owned_bundle.deinit();
    return applyLoadedBundleToPath(allocator, &owned_bundle, input_path, output_path);
}

pub fn applyLoadedBundleToPath(
    allocator: std.mem.Allocator,
    owned_bundle: *const bundle.OwnedBundle,
    input_path: []const u8,
    output_path: []const u8,
) !ApplyReport {
    const manifest = owned_bundle.manifest();

    if (manifest.target.arch != .aarch64) return error.UnsupportedBundleArchitecture;
    if (manifest.target.binary_format != .elf) return error.UnsupportedBundleBinaryFormat;
    if (manifest.payload.object_format != .elf) return error.UnsupportedPayloadObjectFormat;
    if (manifest.hooks.len == 0) return error.MissingBundleHooks;

    var rw = try rewriter.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    // `applyBundle*ToPath` historically returned one `RewriteReport`. Keep that
    // surface stable by returning the final hook's report while still applying
    // every hook in manifest order to the same evolving output image.
    var report: ?ApplyReport = null;
    for (manifest.hooks) |hook| {
        report = switch (hook.kind) {
            .instrument => try rw.addInstrumentHookObject(.{
                .payload_object_bytes = owned_bundle.payload_object,
                .target = hook.target,
                .handler_symbol = hook.handler_symbol,
                .log_message = hook.log_message,
                .expected_bytes = hook.expected_bytes,
                .stolen_instruction_count = hook.stolen_instruction_count,
            }),
            .replace => try rw.addReplaceHookObject(.{
                .payload_object_bytes = owned_bundle.payload_object,
                .target = hook.target,
                .replacement_symbol = hook.handler_symbol,
                .expected_bytes = hook.expected_bytes,
            }),
        };
    }

    try rw.writeToPath(output_path);
    return report.?;
}
