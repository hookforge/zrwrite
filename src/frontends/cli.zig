const std = @import("std");
const bundle = @import("../core/bundle.zig");
const apply = @import("../core/apply.zig");
const payload = @import("../core/payload/root.zig");
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
    var symbol_name: ?[]const u8 = null;

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const flag = args[index];
        if (std.mem.eql(u8, flag, "--input")) {
            index += 1;
            input_path = args[index];
        } else if (std.mem.eql(u8, flag, "--symbol")) {
            index += 1;
            symbol_name = args[index];
        } else {
            return error.InvalidArgument;
        }
    }

    const bytes = try std.fs.cwd().readFileAlloc(allocator, input_path orelse return error.MissingInputPath, std.math.maxInt(usize));
    defer allocator.free(bytes);

    const view = try ElfView.parse(bytes);
    const address = try view.resolveSymbolAddress(symbol_name orelse return error.MissingTargetSymbol);
    const file_offset = try view.addressToOffset(address);

    std.debug.print("symbol={s}\nvirtual_address=0x{x}\nfile_offset=0x{x}\n", .{
        symbol_name.?,
        address,
        file_offset,
    });
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

    fn toHookLocator(self: ParsedLocator) !bundle.HookLocator {
        if (!self.seen) return error.MissingTargetLocator;
        return self.locator;
    }
};

const PendingHook = struct {
    kind: bundle.HookKind = .instrument,
    locator: ParsedLocator = .{},
    handler_symbol: ?[]const u8 = null,
    log_message: []const u8 = "",
    stolen_instruction_count: u8 = 1,

    fn hasAnyField(self: PendingHook) bool {
        return self.handler_symbol != null or
            self.log_message.len != 0 or
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
        \\                 (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off>)
        \\                 [--next-hook --handler-symbol <symbol> [--hook-kind instrument|replace]
        \\                             [--stolen-instructions <count>]
        \\                             (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off>)
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
        \\                  (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off>)
        \\                  [--next-hook --handler-symbol <symbol> [--hook-kind instrument|replace]
        \\                              [--stolen-instructions <count>]
        \\                              (--target-symbol <symbol> | --target-vaddr <addr> | --target-file-offset <off>)
        \\                              [--log-message <message>]]
        \\                  [--log-message <message>]
        \\  zrwrite inspect --input <binary> --symbol <symbol>
        \\
    , .{});
}
