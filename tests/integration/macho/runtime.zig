const builtin = @import("builtin");
const std = @import("std");
const zrwrite = @import("zrwrite");
const common = @import("../common.zig");

test "Mach-O rewriter applies native instrument payload with rodata/data/bss relocations" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_rewrite" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_payload_stateful.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute_stateful.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_payload_stateful.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    const report = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });

    try rw.writeToPath(output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(@constCast(output_bytes));
    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.payload_entry_address < report.stub_address.?);
    try std.testing.expect(report.injection_offset < output_bytes.len);
    try std.testing.expectEqual(report.payload_entry_address, try output_view.offsetToAddress(report.injection_offset));
    try std.testing.expect((try output_view.codeSignatureRange()) == null);
}

test "Mach-O rewriter applies native replace payload with BRANCH26 relocations" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_replace" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_replace_branch_payload.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_replaced" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho/runtime/macho_replace_branch_payload.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    const report = try rw.addReplaceHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .replacement_symbol = "replacement_compute",
    });

    try rw.writeToPath(output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const output_view = try zrwrite.format.macho.View.parse(@constCast(output_bytes));

    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);
    try std.testing.expectEqual(report.payload_entry_address, branch_target);
    try std.testing.expectEqual(report.payload_entry_address, try output_view.offsetToAddress(report.injection_offset));
    try std.testing.expect((try output_view.codeSignatureRange()) == null);
}

test "Mach-O instrument output can be ad-hoc codesigned and executed on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_instrument" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_payload_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-Wl,-no_fixup_chains",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_payload_runtime.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 53);
}

test "Mach-O instrument output with writable payload state can be ad-hoc codesigned and executed on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_stateful" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_payload_stateful_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_stateful_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_payload_stateful.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 53);
}

test "Mach-O large executable payloads prefer synthetic pre-LINKEDIT code while keeping native writable data stable" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_large_stateful" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_payload_large_stateful.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_large_stateful_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute_stateful.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_payload_large_stateful.c",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    const target_view = try zrwrite.format.macho.View.parse(@constCast(input_bytes));
    const payload_layout = try zrwrite.payload.analyzeObjectBytesForFormat(
        allocator,
        .macho,
        payload_bytes,
        "on_hit",
    );
    const split_plan = try target_view.planSplitInjection(
        payload_layout.image_size,
        payload_layout.writable_image_size,
        16,
    );
    try std.testing.expect(split_plan.placement == .mixed);
    try std.testing.expect(split_plan.usesSyntheticSegments());
    try std.testing.expect(split_plan.hasWritableRegion());

    const original_data = try target_view.segmentByName("__DATA");
    const original_linkedit = try target_view.segmentByName("__LINKEDIT");

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const output_view = try zrwrite.format.macho.View.parse(@constCast(output_bytes));

    const shifted_data = try output_view.segmentByName("__DATA");
    try std.testing.expectEqual(original_data.command.fileoff, shifted_data.command.fileoff);
    try std.testing.expectEqual(original_data.command.vmaddr, shifted_data.command.vmaddr);

    const synthetic_text = try output_view.segmentByName("__ZR_TEXT");
    try std.testing.expectEqual(split_plan.executable.payload_base_address, synthetic_text.command.vmaddr);
    const writable_plan = split_plan.writable orelse return error.MissingWritablePayloadImageBase;
    try std.testing.expect(
        writable_plan.payload_base_address >= shifted_data.command.vmaddr and
            writable_plan.payload_base_address < shifted_data.command.vmaddr + shifted_data.command.vmsize,
    );
    try std.testing.expectError(error.SegmentNotFound, output_view.segmentByName("__ZR_DATA"));

    const shifted_linkedit = try output_view.segmentByName("__LINKEDIT");
    try std.testing.expectEqual(
        original_linkedit.command.fileoff + split_plan.synthetic_tail_shift,
        shifted_linkedit.command.fileoff,
    );
    try std.testing.expectEqual(
        original_linkedit.command.vmaddr + split_plan.synthetic_tail_shift,
        shifted_linkedit.command.vmaddr,
    );

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 34);
}

test "Mach-O multiple instrument hooks can share one payload image and writable state" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair_macho_runtime_shared" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_multi_handler_shared_state.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair_macho_runtime_shared_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute_pair.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_multi_handler_shared_state_payload.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    const left_layout = try zrwrite.payload.analyzeObjectBytesForFormat(
        allocator,
        .macho,
        payload_bytes,
        "on_left",
    );
    const right_layout = try zrwrite.payload.analyzeObjectBytesForFormat(
        allocator,
        .macho,
        payload_bytes,
        "on_right",
    );

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    const left_report = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute_left"),
        .handler_symbol = "on_left",
    });
    const right_report = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute_right"),
        .handler_symbol = "on_right",
    });

    try std.testing.expectEqual(
        left_report.payload_entry_address - left_layout.entry_offset,
        right_report.payload_entry_address - right_layout.entry_offset,
    );
    try std.testing.expect(left_report.stub_address.? != right_report.stub_address.?);

    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 32);
}

test "Mach-O zig zrstd payload with multiple default placeholders can be ad-hoc codesigned and executed on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_zig_zrstd" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_zig_zrstd_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_zig_zrstd_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-macos",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "--dep",
        "zrwrite",
        "--dep",
        "zrstd",
        "-Mroot=tests/fixtures/macho/runtime/macho_zrstd_multi_default_runtime.zig",
        "-Mzrwrite=src/root.zig",
        "-Mzrstd=src/zrstd/root.zig",
        emit_bin_arg,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{output_path},
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 53), code),
        else => return error.CommandFailed,
    }

    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "trace next_word block=1 word=2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stdout, "<zrstd: formatted output truncated>") == null);
}

test "Mach-O zig zrstd payload can write rich stderr traces on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_zig_zrstd_stderr" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_zig_zrstd_stderr_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_zig_zrstd_stderr_instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-macos",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "--dep",
        "zrwrite",
        "--dep",
        "zrstd",
        "-Mroot=tests/fixtures/macho/runtime/macho_zrstd_stderr_runtime.zig",
        "-Mzrwrite=src/root.zig",
        "-Mzrstd=src/zrstd/root.zig",
        emit_bin_arg,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{output_path},
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 53), code),
        else => return error.CommandFailed,
    }

    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "stderr hit=1 stage=darwin ok=true\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.stderr, "<zrstd: formatted output truncated>") == null);
}

test "Mach-O replace output can be ad-hoc codesigned and executed on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_replace" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_replace_branch_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_runtime_replaced" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho/runtime/macho_replace_branch_payload.c",
        "-o",
        payload_path,
    });

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addReplaceHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
        .replacement_symbol = "replacement_compute",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 63);
}

test "Mach-O instrument payload resolves external target data through synthetic GOT slots on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_external_data_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_external_data_runtime.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_external_data_target.instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho/shared/macho_external_data_patchpoint.S",
        "tests/fixtures/macho/shared/macho_external_data_target.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-macos",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "-I",
        "include",
        emit_bin_arg,
        "tests/fixtures/elf/zig/zig_external_data_runtime.zig",
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const target_view = try zrwrite.format.macho.View.parse(@constCast(input_bytes));
    try std.testing.expect(target_view.isPie());

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    const layout = try zrwrite.payload.analyzeObjectBytesForFormat(
        allocator,
        .macho,
        payload_bytes,
        "on_hit",
    );
    try std.testing.expect(layout.writable_image_size >= @sizeOf(u64));

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("macho_external_data_patchpoint"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 0);
}

test "Mach-O instrument payload resolves writable internal absolute pointers on macOS arm64" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_internal_pointer_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_internal_pointer_payload.o" });
    defer allocator.free(payload_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_internal_pointer_target.instrumented" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho/shared/macho_external_data_patchpoint.S",
        "tests/fixtures/macho/shared/macho_external_data_target.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-c",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/macho/runtime/macho_internal_pointer_payload.c",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const target_view = try zrwrite.format.macho.View.parse(@constCast(input_bytes));
    try std.testing.expect(target_view.isPie());

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    const layout = try zrwrite.payload.analyzeObjectBytesForFormat(
        allocator,
        .macho,
        payload_bytes,
        "on_hit",
    );
    try std.testing.expect(layout.writable_image_size >= @sizeOf(u64) * 3);

    var rw = try zrwrite.Rewriter.initPath(allocator, input_path);
    defer rw.deinit();

    _ = try rw.addInstrumentHookObjectForFormat(.macho, .{
        .payload_object_bytes = payload_bytes,
        .target = zrwrite.bundle.HookLocator.fromSymbol("macho_external_data_patchpoint"),
        .handler_symbol = "on_hit",
    });
    try rw.writeToPath(output_path);

    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 0);
}
