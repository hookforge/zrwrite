const std = @import("std");
const builtin = @import("builtin");
const bundle = @import("../core/bundle.zig");
const apply = @import("../core/apply.zig");
const image_backend = @import("../core/image_backend.zig");
const payload = @import("../core/payload/root.zig");
const pattern_locator = @import("../core/pattern_locator.zig");
const rewriter = @import("../core/rewriter.zig");

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    dispatchCommand(allocator, args) catch |err| {
        if (payload.lastLinkDiagnosticMessage()) |message| {
            std.log.err("{s}", .{message});
        }
        if (rewriter.lastRewriteDiagnosticMessage()) |message| {
            std.log.err("{s}", .{message});
        }
        std.log.err("{s}", .{@errorName(err)});
        if (isCliUsageError(err)) {
            printUsageForArgs(args);
            std.process.exit(2);
        }
        std.process.exit(1);
    };
}

const Command = enum {
    help,
    init_meta,
    bundle,
    apply,
    rewrite,
    inspect,
    unknown,
};

fn dispatchCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        printUsage();
        return;
    }

    if (isHelpToken(args[1])) {
        printUsage();
        return;
    }

    switch (parseCommand(args[1])) {
        .help => {
            if (args.len >= 3) {
                printCommandUsage(parseCommand(args[2]));
            } else {
                printUsage();
            }
            return;
        },
        .init_meta => try commandInitMeta(args[2..]),
        .bundle => try commandBundle(allocator, args[2..]),
        .apply => try commandApply(allocator, args[2..]),
        .rewrite => try commandRewriteShortcut(allocator, args[2..]),
        .inspect => try commandInspect(allocator, args[2..]),
        .unknown => {
            return error.InvalidArgument;
        },
    }
}

fn commandInitMeta(args: []const []const u8) !void {
    if (isSingleHelpArgument(args)) {
        printInitMetaUsage();
        return;
    }

    var output_path: []const u8 = "bundle.meta.json";
    var force = false;
    var target_arch: bundle.Architecture = .aarch64;
    var target_os: ?bundle.OperatingSystem = null;
    var target_format: ?bundle.BinaryFormat = null;
    var payload_format: ?bundle.ObjectFormat = null;
    var hook_kind: bundle.HookKind = .instrument;
    var target_kind: bundle.HookTargetKind = .virtual_address;
    var payload_object_path: []const u8 = "payload.o";
    var handler_symbol: ?[]const u8 = null;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (flagMatches(flag, "--output", "-o")) {
            output_path = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--force")) {
            force = true;
        } else if (std.mem.eql(u8, flag, "--target-arch")) {
            target_arch = try parseArchitecture(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-os")) {
            target_os = try parseOs(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-format")) {
            target_format = try parseBinaryFormat(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--payload-format")) {
            payload_format = try parseObjectFormat(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--hook-kind")) {
            hook_kind = try parseHookKind(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-kind")) {
            target_kind = try parseHookTargetKind(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--payload-object")) {
            payload_object_path = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--handler-symbol")) {
            handler_symbol = try requireFlagValue(args, &index);
        } else {
            return error.InvalidArgument;
        }
    }

    const resolved_target_os = target_os orelse defaultTemplateTargetOs();
    const resolved_target_format = target_format orelse defaultBinaryFormatForOs(resolved_target_os);
    const resolved_payload_format = payload_format orelse objectFormatForBinaryFormat(resolved_target_format);
    const resolved_handler_symbol = handler_symbol orelse defaultTemplateHandlerSymbol(hook_kind);

    const file = std.fs.cwd().createFile(output_path, .{
        .truncate = true,
        .exclusive = !force,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.MetaTemplateAlreadyExists,
        else => return err,
    };
    defer file.close();

    var file_buffer: [4096]u8 = undefined;
    var file_writer = file.writer(&file_buffer);
    try writeMetaTemplate(&file_writer.interface, .{
        .target_arch = target_arch,
        .target_os = resolved_target_os,
        .target_format = resolved_target_format,
        .payload_object_path = payload_object_path,
        .payload_format = resolved_payload_format,
        .hook_kind = hook_kind,
        .target_kind = target_kind,
        .handler_symbol = resolved_handler_symbol,
    });
    try file_writer.interface.flush();

    std.debug.print("wrote {s}\n", .{output_path});
}

fn commandBundle(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (isSingleHelpArgument(args)) {
        printBundleUsage();
        return;
    }

    var output_path: ?[]const u8 = null;
    var meta_path: ?[]const u8 = null;
    var payload_path: ?[]const u8 = null;
    var target_os = bundle.OperatingSystem.linux;
    var target_format = bundle.BinaryFormat.elf;
    var target_arch = bundle.Architecture.aarch64;
    var payload_format = bundle.ObjectFormat.elf;
    var hooks: std.ArrayList(bundle.HookSpec) = .empty;
    defer hooks.deinit(allocator);
    var pending_hook = PendingHook{};

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (flagMatches(flag, "--output", "-o")) {
            output_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--meta", "-m")) {
            meta_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--payload", "-p")) {
            payload_path = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--handler-symbol")) {
            pending_hook.handler_symbol = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--log-message")) {
            pending_hook.log_message = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--expected-bytes")) {
            pending_hook.expected_bytes = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--stolen-instructions")) {
            pending_hook.stolen_instruction_count = try parseStolenInstructionCount(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--hook-kind")) {
            pending_hook.kind = try parseHookKind(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-symbol")) {
            try pending_hook.locator.setSymbol(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-vaddr")) {
            try pending_hook.locator.setVirtualAddress(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--target-file-offset")) {
            try pending_hook.locator.setFileOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--target-pattern")) {
            try pending_hook.locator.setPattern(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-pattern-offset")) {
            try pending_hook.locator.setPatternOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--next-hook")) {
            try pending_hook.appendTo(allocator, &hooks);
        } else if (std.mem.eql(u8, flag, "--target-os")) {
            target_os = try parseOs(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-format")) {
            target_format = try parseBinaryFormat(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-arch")) {
            target_arch = try parseArchitecture(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--payload-format")) {
            payload_format = try parseObjectFormat(try requireFlagValue(args, &index));
        } else {
            return error.InvalidArgument;
        }
    }

    if (meta_path) |path| {
        if (bundleInlineSpecPresent(
            payload_path,
            target_os,
            target_format,
            target_arch,
            payload_format,
            hooks.items.len,
            pending_hook,
        )) return error.MixedMetaAndInlineBundleFlags;

        var owned_spec = try bundle.loadBuildSpecFromMetaPath(allocator, path);
        defer owned_spec.deinit();
        try bundle.writeToPath(
            allocator,
            output_path orelse return error.MissingOutputPath,
            owned_spec.build_spec,
        );
        return;
    }

    if (pending_hook.hasAnyField()) {
        try pending_hook.appendTo(allocator, &hooks);
    } else if (hooks.items.len == 0) {
        return error.MissingHookSpecification;
    }

    try bundle.writeToPath(allocator, output_path orelse return error.MissingOutputPath, .{
        .target = .{
            .arch = target_arch,
            .os = target_os,
            .binary_format = target_format,
        },
        .payload_object_path = payload_path orelse return error.MissingPayloadPath,
        .payload_object_format = payload_format,
        .hooks = hooks.items,
    });
}

fn commandApply(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (isSingleHelpArgument(args)) {
        printApplyUsage();
        return;
    }

    var bundle_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (flagMatches(flag, "--bundle", "-b")) {
            bundle_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--input", "-i")) {
            input_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--output", "-o")) {
            output_path = try requireFlagValue(args, &index);
        } else {
            return error.InvalidArgument;
        }
    }

    _ = try apply.applyBundleFileToPath(
        allocator,
        bundle_path orelse return error.MissingBundlePath,
        input_path orelse return error.MissingInputPath,
        output_path orelse return error.MissingOutputPath,
    );
}

fn commandRewriteShortcut(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (isSingleHelpArgument(args)) {
        printRewriteUsage();
        return;
    }

    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var meta_path: ?[]const u8 = null;
    var payload_path: ?[]const u8 = null;
    var hooks: std.ArrayList(bundle.HookSpec) = .empty;
    defer hooks.deinit(allocator);
    var pending_hook = PendingHook{};

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (flagMatches(flag, "--input", "-i")) {
            input_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--output", "-o")) {
            output_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--meta", "-m")) {
            meta_path = try requireFlagValue(args, &index);
        } else if (flagMatches(flag, "--payload", "-p")) {
            payload_path = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--handler-symbol")) {
            pending_hook.handler_symbol = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--log-message")) {
            pending_hook.log_message = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--expected-bytes")) {
            pending_hook.expected_bytes = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--stolen-instructions")) {
            pending_hook.stolen_instruction_count = try parseStolenInstructionCount(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--hook-kind")) {
            pending_hook.kind = try parseHookKind(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-symbol")) {
            try pending_hook.locator.setSymbol(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-vaddr")) {
            try pending_hook.locator.setVirtualAddress(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--target-file-offset")) {
            try pending_hook.locator.setFileOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--target-pattern")) {
            try pending_hook.locator.setPattern(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--target-pattern-offset")) {
            try pending_hook.locator.setPatternOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--next-hook")) {
            try pending_hook.appendTo(allocator, &hooks);
        } else {
            return error.InvalidArgument;
        }
    }

    if (meta_path) |path| {
        if (rewriteInlineSpecPresent(payload_path, hooks.items.len, pending_hook)) {
            return error.MixedMetaAndInlineBundleFlags;
        }

        var owned_spec = try bundle.loadBuildSpecFromMetaPath(allocator, path);
        defer owned_spec.deinit();

        const bundle_bytes = try bundle.createBytes(allocator, owned_spec.build_spec);
        defer allocator.free(bundle_bytes);

        _ = try apply.applyBundleBytesToPath(
            allocator,
            bundle_bytes,
            input_path orelse return error.MissingInputPath,
            output_path orelse return error.MissingOutputPath,
        );
        return;
    }

    if (pending_hook.hasAnyField()) {
        try pending_hook.appendTo(allocator, &hooks);
    } else if (hooks.items.len == 0) {
        return error.MissingHookSpecification;
    }

    const bundle_bytes = try bundle.createBytes(allocator, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path orelse return error.MissingPayloadPath,
        .payload_object_format = .elf,
        .hooks = hooks.items,
    });
    defer allocator.free(bundle_bytes);

    _ = try apply.applyBundleBytesToPath(
        allocator,
        bundle_bytes,
        input_path orelse return error.MissingInputPath,
        output_path orelse return error.MissingOutputPath,
    );
}

fn commandInspect(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (isSingleHelpArgument(args)) {
        printInspectUsage();
        return;
    }

    var input_path: ?[]const u8 = null;
    var locator: ParsedLocator = .{};
    var pattern_bytes: usize = 16;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (flagMatches(flag, "--input", "-i")) {
            input_path = try requireFlagValue(args, &index);
        } else if (std.mem.eql(u8, flag, "--symbol")) {
            try locator.setSymbol(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--vaddr")) {
            try locator.setVirtualAddress(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--file-offset")) {
            try locator.setFileOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--pattern")) {
            try locator.setPattern(try requireFlagValue(args, &index));
        } else if (std.mem.eql(u8, flag, "--pattern-offset")) {
            try locator.setPatternOffset(try parseInteger(try requireFlagValue(args, &index)));
        } else if (std.mem.eql(u8, flag, "--pattern-bytes")) {
            pattern_bytes = @intCast(try parseInteger(try requireFlagValue(args, &index)));
        } else {
            return error.InvalidArgument;
        }
    }

    const bytes = try std.fs.cwd().readFileAlloc(allocator, input_path orelse return error.MissingInputPath, std.math.maxInt(usize));
    defer allocator.free(bytes);

    const view = try image_backend.View.parse(bytes);
    const resolved = try resolveInspectLocation(allocator, view, try locator.toHookLocator());

    const exact_len = @min(pattern_bytes, bytes.len - resolved.file_offset);
    const expected_len = @min(@as(usize, 4), exact_len);
    const exact_pattern_hex = try hexStringAlloc(allocator, bytes[resolved.file_offset .. resolved.file_offset + exact_len]);
    defer allocator.free(exact_pattern_hex);
    const expected_hex = try hexStringAlloc(allocator, bytes[resolved.file_offset .. resolved.file_offset + expected_len]);
    defer allocator.free(expected_hex);

    const exact_pattern = try pattern_locator.parseHexPattern(allocator, exact_pattern_hex);
    defer allocator.free(exact_pattern);
    const exact_matches = try pattern_locator.findMatchesInExecutableSegments(allocator, view, exact_pattern, 2);
    defer allocator.free(exact_matches);

    std.debug.print("virtual_address=0x{x}\nfile_offset=0x{x}\n", .{
        resolved.address,
        resolved.file_offset,
    });
    if (resolved.symbol_name) |symbol_name| {
        std.debug.print("symbol={s}\n", .{symbol_name});
    }
    std.debug.print(
        "expected_bytes={s}\npattern_exact={s}\npattern_exact_match_count={s}\n",
        .{
            expected_hex,
            exact_pattern_hex,
            if (exact_matches.len >= 2) ">=2" else "1",
        },
    );
    std.debug.print(
        \\meta_target_pattern={{"kind":"pattern","pattern":"{s}","pattern_offset":"0x0"}}
        \\meta_hook_snippet={{
        \\  "kind":"instrument",
        \\  "target":{{"kind":"pattern","pattern":"{s}","pattern_offset":"0x0"}},
        \\  "expected_bytes":"{s}",
        \\  "handler_symbol":"<fill-me>"
        \\}}
        \\
    ,
        .{ exact_pattern_hex, exact_pattern_hex, expected_hex },
    );
}

const InspectLocation = struct {
    address: u64,
    file_offset: usize,
    symbol_name: ?[]const u8 = null,
};

fn resolveInspectLocation(
    allocator: std.mem.Allocator,
    view: image_backend.View,
    locator: bundle.HookLocator,
) !InspectLocation {
    return switch (locator.kind) {
        .symbol => .{
            .address = try view.resolveSymbolAddress(locator.symbol),
            .file_offset = try view.addressToOffset(try view.resolveSymbolAddress(locator.symbol)),
            .symbol_name = locator.symbol,
        },
        .virtual_address => .{
            .address = locator.virtual_address,
            .file_offset = try view.addressToOffset(locator.virtual_address),
        },
        .file_offset => .{
            .address = try view.offsetToAddress(locator.file_offset),
            .file_offset = @intCast(locator.file_offset),
        },
        .pattern => blk: {
            const parsed_pattern = try pattern_locator.parseHexPattern(allocator, locator.pattern);
            defer allocator.free(parsed_pattern);

            if (locator.pattern_offset >= parsed_pattern.len) return error.InvalidPatternOffset;
            const matches = try pattern_locator.findMatchesInExecutableSegments(allocator, view, parsed_pattern, 2);
            defer allocator.free(matches);

            if (matches.len == 0) return error.PatternNotFound;
            if (matches.len > 1) return error.PatternNotUnique;

            break :blk .{
                .address = matches[0].address + locator.pattern_offset,
                .file_offset = matches[0].file_offset + @as(usize, @intCast(locator.pattern_offset)),
            };
        },
    };
}

fn hexStringAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const digits = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    errdefer allocator.free(out);

    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0xF];
    }
    return out;
}

fn parseArchitecture(value: []const u8) !bundle.Architecture {
    if (std.mem.eql(u8, value, "aarch64")) return .aarch64;
    if (std.mem.eql(u8, value, "x86_64")) return .x86_64;
    return error.InvalidArchitecture;
}

fn parseHookKind(value: []const u8) !bundle.HookKind {
    if (std.mem.eql(u8, value, "instrument")) return .instrument;
    if (std.mem.eql(u8, value, "replace")) return .replace;
    return error.InvalidHookKind;
}

fn parseOs(value: []const u8) !bundle.OperatingSystem {
    if (std.mem.eql(u8, value, "linux")) return .linux;
    if (std.mem.eql(u8, value, "macos")) return .macos;
    return error.InvalidOperatingSystem;
}

fn parseBinaryFormat(value: []const u8) !bundle.BinaryFormat {
    if (std.mem.eql(u8, value, "elf")) return .elf;
    if (std.mem.eql(u8, value, "macho")) return .macho;
    return error.InvalidBinaryFormat;
}

fn parseObjectFormat(value: []const u8) !bundle.ObjectFormat {
    if (std.mem.eql(u8, value, "elf")) return .elf;
    if (std.mem.eql(u8, value, "macho")) return .macho;
    return error.InvalidObjectFormat;
}

fn parseInteger(value: []const u8) !u64 {
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseUnsigned(u64, value[2..], 16);
    }
    return std.fmt.parseUnsigned(u64, value, 10);
}

fn parseStolenInstructionCount(value: []const u8) !u8 {
    const parsed = try parseInteger(value);
    if (parsed == 0 or parsed > std.math.maxInt(u8)) return error.InvalidStolenInstructionCount;
    return @intCast(parsed);
}

fn parseCommand(token: []const u8) Command {
    if (std.mem.eql(u8, token, "help")) return .help;
    if (std.mem.eql(u8, token, "init-meta")) return .init_meta;
    if (std.mem.eql(u8, token, "bundle")) return .bundle;
    if (std.mem.eql(u8, token, "apply")) return .apply;
    if (std.mem.eql(u8, token, "rewrite")) return .rewrite;
    if (std.mem.eql(u8, token, "inspect")) return .inspect;
    return .unknown;
}

fn parseHookTargetKind(value: []const u8) !bundle.HookTargetKind {
    if (std.mem.eql(u8, value, "symbol")) return .symbol;
    if (std.mem.eql(u8, value, "virtual_address")) return .virtual_address;
    if (std.mem.eql(u8, value, "file_offset")) return .file_offset;
    if (std.mem.eql(u8, value, "pattern")) return .pattern;
    return error.InvalidHookTargetKind;
}

fn isSingleHelpArgument(args: []const []const u8) bool {
    return args.len == 1 and
        (isHelpToken(args[0]) or std.mem.eql(u8, args[0], "help"));
}

fn flagMatches(flag: []const u8, long_name: []const u8, short_name: []const u8) bool {
    return std.mem.eql(u8, flag, long_name) or std.mem.eql(u8, flag, short_name);
}

fn requireFlagValue(args: []const []const u8, index: *usize) ![]const u8 {
    index.* += 1;
    if (index.* >= args.len) return error.MissingFlagValue;
    return args[index.*];
}

fn isCliUsageError(err: anyerror) bool {
    return switch (err) {
        error.InvalidArgument,
        error.MissingFlagValue,
        error.MissingBundlePath,
        error.MissingInputPath,
        error.MissingOutputPath,
        error.MissingPayloadPath,
        error.MissingHookSpecification,
        error.MissingHandlerSymbol,
        error.MissingTargetLocator,
        error.MultipleTargetLocators,
        error.MixedMetaAndInlineBundleFlags,
        error.InvalidArchitecture,
        error.InvalidHookKind,
        error.InvalidHookTargetKind,
        error.InvalidOperatingSystem,
        error.InvalidBinaryFormat,
        error.InvalidObjectFormat,
        error.InvalidPatternOffset,
        error.InvalidStolenInstructionCount,
        => true,
        else => false,
    };
}

const MetaTemplateOptions = struct {
    target_arch: bundle.Architecture,
    target_os: bundle.OperatingSystem,
    target_format: bundle.BinaryFormat,
    payload_object_path: []const u8,
    payload_format: bundle.ObjectFormat,
    hook_kind: bundle.HookKind,
    target_kind: bundle.HookTargetKind,
    handler_symbol: []const u8,
};

fn defaultTemplateTargetOs() bundle.OperatingSystem {
    return switch (builtin.os.tag) {
        .macos => .macos,
        else => .linux,
    };
}

fn defaultBinaryFormatForOs(os: bundle.OperatingSystem) bundle.BinaryFormat {
    return switch (os) {
        .linux => .elf,
        .macos => .macho,
    };
}

fn objectFormatForBinaryFormat(format: bundle.BinaryFormat) bundle.ObjectFormat {
    return switch (format) {
        .elf => .elf,
        .macho => .macho,
    };
}

fn defaultTemplateHandlerSymbol(kind: bundle.HookKind) []const u8 {
    return switch (kind) {
        .instrument => "on_hit",
        .replace => "replacement_entry",
    };
}

// Emit the template manually so the output stays stable and the placeholder
// values are obvious to users editing the file for the first time.
fn writeMetaTemplate(writer: anytype, options: MetaTemplateOptions) !void {
    try writer.writeAll("{\n");
    try writer.writeAll("  \"target\": {\n");
    try writer.writeAll("    \"arch\": ");
    try writeJsonString(writer, @tagName(options.target_arch));
    try writer.writeAll(",\n    \"os\": ");
    try writeJsonString(writer, @tagName(options.target_os));
    try writer.writeAll(",\n    \"binary_format\": ");
    try writeJsonString(writer, @tagName(options.target_format));
    try writer.writeAll("\n  },\n");
    try writer.writeAll("  \"payload\": {\n");
    try writer.writeAll("    \"object_path\": ");
    try writeJsonString(writer, options.payload_object_path);
    try writer.writeAll(",\n    \"object_format\": ");
    try writeJsonString(writer, @tagName(options.payload_format));
    try writer.writeAll("\n  },\n");
    try writer.writeAll("  \"hooks\": [\n");
    try writer.writeAll("    {\n");
    try writer.writeAll("      \"kind\": ");
    try writeJsonString(writer, @tagName(options.hook_kind));
    try writer.writeAll(",\n");
    try writer.writeAll("      \"target\": {\n");
    try writer.writeAll("        \"kind\": ");
    try writeJsonString(writer, @tagName(options.target_kind));
    switch (options.target_kind) {
        .symbol => {
            try writer.writeAll(",\n        \"symbol\": ");
            try writeJsonString(writer, "<fill-me-symbol>");
        },
        .virtual_address => {
            try writer.writeAll(",\n        \"virtual_address\": ");
            try writeJsonString(writer, "<fill-me-linked-vaddr>");
        },
        .file_offset => {
            try writer.writeAll(",\n        \"file_offset\": ");
            try writeJsonString(writer, "<fill-me-file-offset>");
        },
        .pattern => {
            try writer.writeAll(",\n        \"pattern\": ");
            try writeJsonString(writer, "<fill-me-hex-pattern>");
            try writer.writeAll(",\n        \"pattern_offset\": ");
            try writeJsonString(writer, "0x0");
        },
    }
    try writer.writeAll("\n      }");
    if (options.hook_kind == .instrument) {
        try writer.writeAll(",\n      \"expected_bytes\": ");
        try writeJsonString(writer, "<fill-me-expected-bytes>");
    }
    try writer.writeAll(",\n      \"handler_symbol\": ");
    try writeJsonString(writer, options.handler_symbol);
    try writer.writeAll("\n    }\n");
    try writer.writeAll("  ]\n");
    try writer.writeAll("}\n");
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try std.json.Stringify.value(value, .{}, writer);
}

const ParsedLocator = struct {
    seen: bool = false,
    locator: bundle.HookLocator = .{},

    fn setSymbol(self: *ParsedLocator, value: []const u8) !void {
        if (self.seen) return error.MultipleTargetLocators;
        self.seen = true;
        self.locator = bundle.HookLocator.fromSymbol(value);
    }

    fn setVirtualAddress(self: *ParsedLocator, value: u64) !void {
        if (self.seen) return error.MultipleTargetLocators;
        self.seen = true;
        self.locator = bundle.HookLocator.fromVirtualAddress(value);
    }

    fn setFileOffset(self: *ParsedLocator, value: u64) !void {
        if (self.seen) return error.MultipleTargetLocators;
        self.seen = true;
        self.locator = bundle.HookLocator.fromFileOffset(value);
    }

    fn setPattern(self: *ParsedLocator, value: []const u8) !void {
        if (self.seen and self.locator.kind != .pattern) return error.MultipleTargetLocators;
        self.seen = true;
        if (self.locator.kind != .pattern) {
            self.locator = bundle.HookLocator.fromPattern(value, 0);
        } else {
            self.locator.pattern = value;
        }
    }

    fn setPatternOffset(self: *ParsedLocator, value: u64) !void {
        if (self.seen and self.locator.kind != .pattern) return error.MultipleTargetLocators;
        self.seen = true;
        if (self.locator.kind != .pattern) {
            self.locator = bundle.HookLocator.fromPattern("", value);
        } else {
            self.locator.pattern_offset = value;
        }
    }

    fn toHookLocator(self: ParsedLocator) !bundle.HookLocator {
        if (!self.seen) return error.MissingTargetLocator;
        if (self.locator.kind == .pattern and self.locator.pattern.len == 0) {
            return error.MissingTargetLocator;
        }
        return self.locator;
    }
};

const PendingHook = struct {
    kind: bundle.HookKind = .instrument,
    locator: ParsedLocator = .{},
    handler_symbol: ?[]const u8 = null,
    log_message: []const u8 = "",
    expected_bytes: []const u8 = "",
    stolen_instruction_count: u8 = 1,

    fn hasAnyField(self: PendingHook) bool {
        return self.handler_symbol != null or
            self.log_message.len != 0 or
            self.expected_bytes.len != 0 or
            self.locator.seen or
            self.kind != .instrument or
            self.stolen_instruction_count != 1;
    }

    fn appendTo(
        self: *PendingHook,
        allocator: std.mem.Allocator,
        hooks: *std.ArrayList(bundle.HookSpec),
    ) !void {
        if (!self.hasAnyField()) return error.MissingHookSpecification;

        try hooks.append(allocator, .{
            .kind = self.kind,
            .target = try self.locator.toHookLocator(),
            .handler_symbol = self.handler_symbol orelse return error.MissingHandlerSymbol,
            .log_message = self.log_message,
            .expected_bytes = self.expected_bytes,
            .stolen_instruction_count = self.stolen_instruction_count,
        });
        self.* = .{};
    }
};

fn bundleInlineSpecPresent(
    payload_path: ?[]const u8,
    target_os: bundle.OperatingSystem,
    target_format: bundle.BinaryFormat,
    target_arch: bundle.Architecture,
    payload_format: bundle.ObjectFormat,
    hooks_len: usize,
    pending_hook: PendingHook,
) bool {
    return payload_path != null or
        target_os != .linux or
        target_format != .elf or
        target_arch != .aarch64 or
        payload_format != .elf or
        hooks_len != 0 or
        pending_hook.hasAnyField();
}

fn rewriteInlineSpecPresent(
    payload_path: ?[]const u8,
    hooks_len: usize,
    pending_hook: PendingHook,
) bool {
    return payload_path != null or hooks_len != 0 or pending_hook.hasAnyField();
}

fn isHelpToken(token: []const u8) bool {
    return std.mem.eql(u8, token, "-h") or
        std.mem.eql(u8, token, "--help");
}

fn printUsageForArgs(args: []const []const u8) void {
    if (args.len < 2 or isHelpToken(args[1])) {
        printUsage();
        return;
    }

    const command = parseCommand(args[1]);
    if (command == .help) {
        if (args.len >= 3) {
            printCommandUsage(parseCommand(args[2]));
        } else {
            printUsage();
        }
        return;
    }

    printCommandUsage(command);
}

fn printCommandUsage(command: Command) void {
    switch (command) {
        .init_meta => printInitMetaUsage(),
        .bundle => printBundleUsage(),
        .apply => printApplyUsage(),
        .rewrite => printRewriteUsage(),
        .inspect => printInspectUsage(),
        .help, .unknown => printUsage(),
    }
}

fn printInitMetaUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite init-meta [--output|-o <bundle.meta.json>] [--force]
        \\                    [--hook-kind instrument|replace]
        \\                    [--target-kind symbol|virtual_address|file_offset|pattern]
        \\                    [--target-arch aarch64|x86_64]
        \\                    [--target-os linux|macos]
        \\                    [--target-format elf|macho]
        \\                    [--payload-object <payload.o>]
        \\                    [--payload-format elf|macho]
        \\                    [--handler-symbol <symbol>]
        \\
    , .{});
}

fn printBundleUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite bundle --output|-o <patch.zrpb> --payload|-p <handler.o> --handler-symbol <symbol>
        \\                 [--meta|-m <bundle.meta.json>]
        \\                 [--hook-kind instrument|replace]
        \\                 [--stolen-instructions <count>]
        \\                 [--expected-bytes <hex>]
        \\                 (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off> |
        \\                  --target-pattern <hex> [--target-pattern-offset <off>])
        \\                 [--next-hook --handler-symbol <symbol> [--hook-kind instrument|replace]
        \\                             [--stolen-instructions <count>]
        \\                             [--expected-bytes <hex>]
        \\                             (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off> |
        \\                              --target-pattern <hex> [--target-pattern-offset <off>])
        \\                             [--log-message <message>]]
        \\                 [--log-message <message>] [--target-arch aarch64|x86_64]
        \\                 [--target-os linux|macos] [--target-format elf|macho]
        \\                 [--payload-format elf|macho]
        \\
    , .{});
}

fn printApplyUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite apply --bundle|-b <patch.zrpb> --input|-i <binary> --output|-o <binary>
        \\
    , .{});
}

fn printRewriteUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite rewrite --input|-i <binary> --output|-o <binary> --payload|-p <handler.o>
        \\                  [--meta|-m <bundle.meta.json>]
        \\                  --handler-symbol <symbol>
        \\                  [--hook-kind instrument|replace]
        \\                  [--stolen-instructions <count>]
        \\                  [--expected-bytes <hex>]
        \\                  (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off> |
        \\                   --target-pattern <hex> [--target-pattern-offset <off>])
        \\                  [--next-hook --handler-symbol <symbol> [--hook-kind instrument|replace]
        \\                              [--stolen-instructions <count>]
        \\                              [--expected-bytes <hex>]
        \\                              (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off> |
        \\                               --target-pattern <hex> [--target-pattern-offset <off>])
        \\                              [--log-message <message>]]
        \\                  [--log-message <message>]
        \\
    , .{});
}

fn printInspectUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite inspect --input|-i <binary>
        \\                  (--symbol <symbol> | --vaddr <addr> | --file-offset <off> |
        \\                   --pattern <hex> [--pattern-offset <off>])
        \\                  [--pattern-bytes <count>]
        \\
    , .{});
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite help [init-meta|bundle|apply|rewrite|inspect]
        \\  zrwrite --help
        \\
        \\
    , .{});
    printInitMetaUsage();
    printBundleUsage();
    printApplyUsage();
    printRewriteUsage();
    printInspectUsage();
}
