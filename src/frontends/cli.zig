const std = @import("std");
const bundle = @import("../core/bundle.zig");
const apply = @import("../core/apply.zig");
const payload = @import("../core/payload/root.zig");
const pattern_locator = @import("../core/pattern_locator.zig");
const rewriter = @import("../core/rewriter.zig");
const ElfView = @import("../format/elf/root.zig").View;

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
        return err;
    };
}

fn dispatchCommand(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        printUsage();
        return;
    }

    if (std.mem.eql(u8, args[1], "bundle")) {
        try commandBundle(allocator, args[2..]);
    } else if (std.mem.eql(u8, args[1], "apply")) {
        try commandApply(allocator, args[2..]);
    } else if (std.mem.eql(u8, args[1], "rewrite")) {
        try commandRewriteShortcut(allocator, args[2..]);
    } else if (std.mem.eql(u8, args[1], "inspect")) {
        try commandInspect(allocator, args[2..]);
    } else {
        printUsage();
        return error.InvalidArgument;
    }
}

fn commandBundle(allocator: std.mem.Allocator, args: []const []const u8) !void {
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
        if (std.mem.eql(u8, flag, "--output")) {
            index += 1;
            output_path = args[index];
        } else if (std.mem.eql(u8, flag, "--meta")) {
            index += 1;
            meta_path = args[index];
        } else if (std.mem.eql(u8, flag, "--payload")) {
            index += 1;
            payload_path = args[index];
        } else if (std.mem.eql(u8, flag, "--handler-symbol")) {
            index += 1;
            pending_hook.handler_symbol = args[index];
        } else if (std.mem.eql(u8, flag, "--log-message")) {
            index += 1;
            pending_hook.log_message = args[index];
        } else if (std.mem.eql(u8, flag, "--expected-bytes")) {
            index += 1;
            pending_hook.expected_bytes = args[index];
        } else if (std.mem.eql(u8, flag, "--stolen-instructions")) {
            index += 1;
            pending_hook.stolen_instruction_count = try parseStolenInstructionCount(args[index]);
        } else if (std.mem.eql(u8, flag, "--hook-kind")) {
            index += 1;
            pending_hook.kind = try parseHookKind(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-symbol")) {
            index += 1;
            try pending_hook.locator.setSymbol(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-vaddr")) {
            index += 1;
            try pending_hook.locator.setVirtualAddress(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--target-file-offset")) {
            index += 1;
            try pending_hook.locator.setFileOffset(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--target-pattern")) {
            index += 1;
            try pending_hook.locator.setPattern(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-pattern-offset")) {
            index += 1;
            try pending_hook.locator.setPatternOffset(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--next-hook")) {
            try pending_hook.appendTo(allocator, &hooks);
        } else if (std.mem.eql(u8, flag, "--target-os")) {
            index += 1;
            target_os = try parseOs(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-format")) {
            index += 1;
            target_format = try parseBinaryFormat(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-arch")) {
            index += 1;
            target_arch = try parseArchitecture(args[index]);
        } else if (std.mem.eql(u8, flag, "--payload-format")) {
            index += 1;
            payload_format = try parseObjectFormat(args[index]);
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
    var bundle_path: ?[]const u8 = null;
    var input_path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--bundle")) {
            index += 1;
            bundle_path = args[index];
        } else if (std.mem.eql(u8, flag, "--input")) {
            index += 1;
            input_path = args[index];
        } else if (std.mem.eql(u8, flag, "--output")) {
            index += 1;
            output_path = args[index];
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
        if (std.mem.eql(u8, flag, "--input")) {
            index += 1;
            input_path = args[index];
        } else if (std.mem.eql(u8, flag, "--output")) {
            index += 1;
            output_path = args[index];
        } else if (std.mem.eql(u8, flag, "--meta")) {
            index += 1;
            meta_path = args[index];
        } else if (std.mem.eql(u8, flag, "--payload")) {
            index += 1;
            payload_path = args[index];
        } else if (std.mem.eql(u8, flag, "--handler-symbol")) {
            index += 1;
            pending_hook.handler_symbol = args[index];
        } else if (std.mem.eql(u8, flag, "--log-message")) {
            index += 1;
            pending_hook.log_message = args[index];
        } else if (std.mem.eql(u8, flag, "--expected-bytes")) {
            index += 1;
            pending_hook.expected_bytes = args[index];
        } else if (std.mem.eql(u8, flag, "--stolen-instructions")) {
            index += 1;
            pending_hook.stolen_instruction_count = try parseStolenInstructionCount(args[index]);
        } else if (std.mem.eql(u8, flag, "--hook-kind")) {
            index += 1;
            pending_hook.kind = try parseHookKind(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-symbol")) {
            index += 1;
            try pending_hook.locator.setSymbol(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-vaddr")) {
            index += 1;
            try pending_hook.locator.setVirtualAddress(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--target-file-offset")) {
            index += 1;
            try pending_hook.locator.setFileOffset(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--target-pattern")) {
            index += 1;
            try pending_hook.locator.setPattern(args[index]);
        } else if (std.mem.eql(u8, flag, "--target-pattern-offset")) {
            index += 1;
            try pending_hook.locator.setPatternOffset(try parseInteger(args[index]));
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
    var input_path: ?[]const u8 = null;
    var locator: ParsedLocator = .{};
    var pattern_bytes: usize = 16;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--input")) {
            index += 1;
            input_path = args[index];
        } else if (std.mem.eql(u8, flag, "--symbol")) {
            index += 1;
            try locator.setSymbol(args[index]);
        } else if (std.mem.eql(u8, flag, "--vaddr")) {
            index += 1;
            try locator.setVirtualAddress(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--file-offset")) {
            index += 1;
            try locator.setFileOffset(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--pattern")) {
            index += 1;
            try locator.setPattern(args[index]);
        } else if (std.mem.eql(u8, flag, "--pattern-offset")) {
            index += 1;
            try locator.setPatternOffset(try parseInteger(args[index]));
        } else if (std.mem.eql(u8, flag, "--pattern-bytes")) {
            index += 1;
            pattern_bytes = @intCast(try parseInteger(args[index]));
        } else {
            return error.InvalidArgument;
        }
    }

    const bytes = try std.fs.cwd().readFileAlloc(allocator, input_path orelse return error.MissingInputPath, std.math.maxInt(usize));
    defer allocator.free(bytes);

    const view = try ElfView.parse(bytes);
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
    view: ElfView,
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

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  zrwrite bundle --output <patch.zrpb> --payload <handler.o> --handler-symbol <symbol>
        \\                 [--meta <bundle.meta.json>]
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
        \\  zrwrite apply --bundle <patch.zrpb> --input <binary> --output <binary>
        \\  zrwrite rewrite --input <binary> --output <binary> --payload <handler.o>
        \\                  [--meta <bundle.meta.json>]
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
        \\  zrwrite inspect --input <binary>
        \\                  (--symbol <symbol> | --vaddr <addr> | --file-offset <off> |
        \\                   --pattern <hex> [--pattern-offset <off>])
        \\                  [--pattern-bytes <count>]
        \\
    , .{});
}
