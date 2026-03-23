const std = @import("std");
const zrwrite = @import("zrwrite");

test "bundle -> apply appends instrument payload, patches compute, and keeps callback ABI stable" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute.patched" });
    defer allocator.free(output_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/payload.c",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite: compute hit\n",
            },
        },
    });

    var loaded_bundle = try zrwrite.bundle.loadFromPath(allocator, bundle_path);
    defer loaded_bundle.deinit();
    try std.testing.expectEqual(@as(usize, 1), loaded_bundle.manifest().hooks.len);
    try std.testing.expectEqual(zrwrite.bundle.Architecture.aarch64, loaded_bundle.manifest().target.arch);
    try std.testing.expectEqual(zrwrite.bundle.HookTargetKind.symbol, loaded_bundle.manifest().hooks[0].target.kind);
    try std.testing.expectEqualStrings("compute", loaded_bundle.manifest().hooks[0].target.symbol);

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const view = try zrwrite.elf.View.parse(@constCast(output_bytes));
    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite: compute hit\n") != null);

    const last_load_index = try view.lastLoadSegmentIndex();
    const last_load = view.phdrs[last_load_index];
    try std.testing.expect((last_load.p_flags & std.elf.PF_X) != 0);
    try std.testing.expect(last_load.p_filesz > 0);
    try std.testing.expect(last_load.p_memsz >= last_load.p_filesz);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const input_last_load_index = try input_view.lastLoadSegmentIndex();
    const input_last_load = input_view.phdrs[input_last_load_index];
    const expected_injection_offset = std.mem.alignForward(
        usize,
        @as(usize, @intCast(input_last_load.p_offset + input_last_load.p_memsz)),
        16,
    );
    try std.testing.expect(output_bytes.len > input_bytes.len);
    try std.testing.expect(report.payload_entry_address < report.stub_address.?);
    try std.testing.expect(report.trampoline_address.? < report.stub_address.?);
    try std.testing.expectEqual(expected_injection_offset, report.injection_offset);

    try std.testing.expectEqual(@sizeOf(zrwrite.HookContext), @sizeOf(@import("zrwrite").sdk.HookContext));
    try std.testing.expectEqual(@offsetOf(zrwrite.HookContext, "pc"), @offsetOf(@import("zrwrite").sdk.HookContext, "pc"));
}

test "bundle -> apply supports replace hook via virtual address locator" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "replace_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_replace.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute.replaced" });
    defer allocator.free(output_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O3",
        "-g0",
        "-fno-pic",
        "-no-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-O3",
        "-g0",
        "-fno-pic",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/replace_payload.c",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("compute");

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
                .kind = .replace,
                .target = zrwrite.bundle.HookLocator.fromVirtualAddress(target_address),
                .handler_symbol = "replacement_compute",
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const branch_ptr: *const [4]u8 = @ptrCast(output_bytes[report.target_file_offset .. report.target_file_offset + 4].ptr);
    const branch_opcode = std.mem.readInt(u32, branch_ptr, .little);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, report.target_address);

    try std.testing.expectEqual(report.payload_entry_address, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expectEqual(@as(?u64, null), report.stub_address);
    try std.testing.expect(output_bytes.len > input_bytes.len);
}

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

    try runCommand(allocator, &.{
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
        "tests/fixtures/replay_adrp_target.S",
        "tests/fixtures/replay_adrp_main.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/noop_payload.c",
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/x16_resume_target.S",
        "tests/fixtures/x16_resume_main.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/x16_resume_payload.c",
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/x17_resume_target.S",
        "tests/fixtures/x17_resume_main.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/x17_resume_payload.c",
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

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        std.debug.print("command failed: {s}\n{s}\n{s}\n", .{
            argv[0],
            result.stdout,
            result.stderr,
        });
        return error.CommandFailed;
    }
}
