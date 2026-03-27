const std = @import("std");
const zrwrite = @import("zrwrite");
const common = @import("../common.zig");

test "bundle -> apply accepts semantic replay instrument hook for linker-relaxed adr patchpoints" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "replay_adrp" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "noop_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "replay_adrp.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "replay_adrp.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/replay_adrp_target.S",
        "tests/fixtures/elf/replay/replay_adrp_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("load_magic_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite semantic replay hit\n",
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expect(output_bytes.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite semantic replay hit\n") != null);
}

test "bundle -> apply keeps raw trampoline path available for x16 resume smoke" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x16_resume" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x16_resume_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x16_resume.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x16_resume.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/x16_resume_target.S",
        "tests/fixtures/elf/replay/x16_resume_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/elf/replay/x16_resume_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("x16_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite x16 resume hit\n",
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite x16 resume hit\n") != null);
}

test "bundle -> apply keeps direct-resume path available for x17 resume smoke" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x17_resume" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x17_resume_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x17_resume.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "x17_resume.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/x17_resume_target.S",
        "tests/fixtures/elf/replay/x17_resume_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/elf/replay/x17_resume_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("x17_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite x17 resume hit\n",
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite x17 resume hit\n") != null);
}

test "bundle -> apply replays widened straight-line patch windows" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/wide_window_target.S",
        "tests/fixtures/elf/replay/wide_window_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("wide_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite widened window hit\n",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("wide_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[target_file_offset .. target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try common.readLeU32(output_bytes, target_file_offset + 4));
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try common.readLeU32(output_bytes, target_file_offset + 8));
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try common.readLeU32(output_bytes, target_file_offset + 12));
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite widened window hit\n") != null);
}

test "bundle -> apply replays widened semantic-prefix windows for adrp + add + ldr" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_adrp" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_adrp_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_adrp_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_adrp.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/wide_semantic_adrp_target.S",
        "tests/fixtures/elf/replay/wide_semantic_adrp_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("semantic_wide_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite wide semantic replay hit\n",
                .stolen_instruction_count = 3,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("semantic_wide_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 4),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 8),
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite wide semantic replay hit\n") != null);
}

test "bundle -> apply replays widened terminal branch windows for cmp + b.cond" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/terminal_branch_target.S",
        "tests/fixtures/elf/replay/terminal_branch_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("terminal_branch_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite terminal branch replay hit\n",
                .stolen_instruction_count = 2,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("terminal_branch_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 4),
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite terminal branch replay hit\n") != null);
}

test "bundle -> apply supports O2 terminal-branch samples through virtual-address patching" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_o2" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_o2_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_o2_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_o2.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O2",
        "-g0",
        "-static",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/terminal_branch_o2.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("stripped_terminal_branch");

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromVirtualAddress(target_address),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite O2 terminal branch replay hit\n",
                .stolen_instruction_count = 2,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite O2 terminal branch replay hit\n") != null);
}

test "bundle -> apply replays widened add-immediate terminal-branch windows" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "add_terminal_branch_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "add_terminal_branch_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "add_terminal_branch_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "add_terminal_branch_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/add_terminal_branch_target.S",
        "tests/fixtures/elf/replay/add_terminal_branch_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("add_terminal_branch_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite add terminal branch replay hit\n",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("add_terminal_branch_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 4),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 8),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try common.readLeU32(output_bytes, target_file_offset + 12),
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite add terminal branch replay hit\n") != null);
}

test "bundle -> apply supports widened straight-line patch windows above four instructions" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window8_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window8_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window8_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window8_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/wide_window8_target.S",
        "tests/fixtures/elf/replay/wide_window8_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("wide8_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite widened window 8 hit\n",
                .stolen_instruction_count = 8,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("wide8_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    for (1..8) |index| {
        try std.testing.expectEqual(
            zrwrite.aarch64.nop_instruction,
            try common.readLeU32(output_bytes, target_file_offset + index * 4),
        );
    }
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite widened window 8 hit\n") != null);
}

test "bundle -> apply retargets incoming branches into widened raw windows" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_branch_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_branch_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_branch_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_window_branch_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/wide_window_branch_target.S",
        "tests/fixtures/elf/replay/wide_window_branch_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("wide_branch_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const output_view = try zrwrite.elf.View.parse(@constCast(output_bytes));
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const branch_source_address = try input_view.resolveSymbolAddress("branch_to_mid");
    const branch_source_file_offset = try input_view.addressToOffset(branch_source_address);
    const retargeted_opcode = try common.readLeU32(output_bytes, branch_source_file_offset);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(retargeted_opcode, branch_source_address);
    const trampoline_file_offset = try output_view.addressToOffset(report.trampoline_address.?);

    try std.testing.expectEqual(
        report.trampoline_address.? + 4,
        retargeted_target,
    );
    try std.testing.expectEqual(
        try common.readLeU32(output_bytes, trampoline_file_offset + 4),
        try common.readLeU32(input_bytes, try input_view.addressToOffset(try input_view.resolveSymbolAddress("wide_branch_mid"))),
    );
}

test "bundle -> apply retargets incoming branches into semantic terminal-branch interior steps" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_interior_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_interior_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_interior_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "terminal_branch_interior_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/terminal_branch_interior_target.S",
        "tests/fixtures/elf/replay/terminal_branch_interior_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("terminal_branch_interior_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 2,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const branch_source_address = try input_view.resolveSymbolAddress("branch_to_terminal_branch_mid");
    const branch_source_file_offset = try input_view.addressToOffset(branch_source_address);
    const retargeted_opcode = try common.readLeU32(output_bytes, branch_source_file_offset);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(retargeted_opcode, branch_source_address);
    const original_mid_address = try input_view.resolveSymbolAddress("terminal_branch_interior_patchpoint") + 4;

    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expect(retargeted_target != original_mid_address);
    try std.testing.expect(retargeted_target != report.stub_address.?);
}

test "bundle -> apply retargets incoming branches into widened semantic-prefix raw tails" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_branch_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_branch_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_branch_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "wide_semantic_branch_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/wide_semantic_branch_target.S",
        "tests/fixtures/elf/replay/wide_semantic_branch_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("semantic_branch_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite semantic interior hit\n",
                .stolen_instruction_count = 3,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const branch_source_address = try input_view.resolveSymbolAddress("branch_to_semantic_branch_mid");
    const branch_source_file_offset = try input_view.addressToOffset(branch_source_address);
    const branch_opcode = try common.readLeU32(output_bytes, branch_source_file_offset + 4);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, branch_source_address + 4);

    try std.testing.expectEqual(
        report.trampoline_address.? + 4,
        retargeted_target,
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite semantic interior hit\n") != null);
}

test "bundle -> apply retargets incoming branches into semantic-prefix interior steps" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "semantic_prefix_interior_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "semantic_prefix_interior_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "semantic_prefix_interior_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "semantic_prefix_interior_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/semantic_prefix_interior_target.S",
        "tests/fixtures/elf/replay/semantic_prefix_interior_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("semantic_prefix_interior_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const branch_source_address = try input_view.resolveSymbolAddress("branch_to_semantic_prefix_interior_mid");
    const branch_source_file_offset = try input_view.addressToOffset(branch_source_address);
    const retargeted_opcode = try common.readLeU32(output_bytes, branch_source_file_offset);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(retargeted_opcode, branch_source_address);
    const original_mid_address = try input_view.resolveSymbolAddress("semantic_prefix_interior_patchpoint") + 4;

    try std.testing.expect(retargeted_target != original_mid_address);
    try std.testing.expect(retargeted_target > report.trampoline_address.?);
    try std.testing.expect(retargeted_target < report.stub_address.?);
}

test "bundle -> apply still rejects unsupported semantic-prefix interior steps" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "unsupported_semantic_interior_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "unsupported_semantic_interior_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "unsupported_semantic_interior_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "unsupported_semantic_interior_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/unsupported_semantic_interior_target.S",
        "tests/fixtures/elf/replay/unsupported_semantic_interior_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/noop_payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("unsupported_semantic_interior_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 3,
            },
        },
    });

    try std.testing.expectError(
        error.IncomingBranchIntoPatchWindow,
        zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path),
    );
}

test "bundle -> apply falls back to a PIE-safe long detour when stub is out of branch range" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "far_detour_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "far_detour_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "far_detour_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "far_detour_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/far_detour_target.S",
        "tests/fixtures/elf/replay/far_detour_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/payload.c",
        "-o",
        payload_path,
    });

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("far_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);

    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("far_patchpoint");
    const target_file_offset = try input_view.addressToOffset(target_address);

    try std.testing.expect(report.stub_address.? - report.target_address > 0x07FF_FFFC);

    const expected_detour = try zrwrite.aarch64.buildLongDetour(target_address, report.stub_address.?);
    try std.testing.expectEqualSlices(
        u8,
        &expected_detour,
        output_bytes[target_file_offset .. target_file_offset + zrwrite.aarch64.long_detour_size],
    );
}

test "bundle -> apply emits BTI-compatible stub and trampoline entries when the input advertises BTI" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "bti_far_detour_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "bti_far_detour_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "bti_far_detour_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "bti_far_detour_target.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-static",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/elf/replay/bti_far_detour_target.S",
        "tests/fixtures/elf/replay/bti_far_detour_main.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-fPIC",
        "-g0",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "-I",
        "include",
        "tests/fixtures/shared/payload.c",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    try std.testing.expect(input_view.hasAarch64BtiProperty());

    try zrwrite.bundle.writeToPath(allocator, bundle_path, .{
        .target = .{
            .arch = .aarch64,
            .os = .linux,
            .binary_format = .elf,
        },
        .payload_object_path = payload_path,
        .payload_object_format = .elf,
        .hooks = &.{
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("bti_far_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 4,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const output_view = try zrwrite.elf.View.parse(@constCast(output_bytes));

    const stub_file_offset = try output_view.addressToOffset(report.stub_address.?);
    const trampoline_file_offset = try output_view.addressToOffset(report.trampoline_address.?);

    try std.testing.expectEqual(
        zrwrite.aarch64.bti_jc_instruction,
        try common.readLeU32(output_bytes, stub_file_offset),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.bti_jc_instruction,
        try common.readLeU32(output_bytes, trampoline_file_offset),
    );
}
