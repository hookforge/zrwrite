const std = @import("std");
const zrwrite = @import("zrwrite");
const common = @import("../common.zig");

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

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/compute.c",
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

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/compute.c",
        "-o",
        input_path,
    });

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/replace_payload.c",
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

test "bundle -> apply supports multiple instrument hooks in one ELF rewrite" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/compute_pair.c",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("compute_left"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite: pair hit\n",
            },
            .{
                .kind = .instrument,
                .target = zrwrite.bundle.HookLocator.fromSymbol("compute_right"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite: pair hit\n",
            },
        },
    });

    var loaded_bundle = try zrwrite.bundle.loadFromPath(allocator, bundle_path);
    defer loaded_bundle.deinit();
    try std.testing.expectEqual(@as(usize, 2), loaded_bundle.manifest().hooks.len);

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const left_address = try input_view.resolveSymbolAddress("compute_left");
    const right_address = try input_view.resolveSymbolAddress("compute_right");
    const left_file_offset = try input_view.addressToOffset(left_address);
    const right_file_offset = try input_view.addressToOffset(right_address);

    const left_branch_opcode = try common.readLeU32(output_bytes, left_file_offset);
    const right_branch_opcode = try common.readLeU32(output_bytes, right_file_offset);
    const left_branch_target = try zrwrite.aarch64.decodeBranchTarget(left_branch_opcode, left_address);
    const right_branch_target = try zrwrite.aarch64.decodeBranchTarget(right_branch_opcode, right_address);

    try std.testing.expect(left_branch_target != right_branch_target);
    try std.testing.expect(left_branch_target > left_address);
    try std.testing.expect(right_branch_target > right_address);
    try std.testing.expectEqual(report.stub_address.?, right_branch_target);
    try std.testing.expectEqual(2, common.countOccurrences(output_bytes, "zrwrite: pair hit\n"));
    try std.testing.expect(output_bytes.len > input_bytes.len);
}

test "bundle meta json supports multiple hooks and resolves payload paths relative to the meta file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("payloads");
    try tmp.dir.makePath("meta");

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payloads", "payload.o" });
    defer allocator.free(payload_path);
    const meta_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "meta", "bundle.meta.json" });
    defer allocator.free(meta_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair.meta.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_pair.meta.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/compute_pair.c",
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
    const left_address = try input_view.resolveSymbolAddress("compute_left");
    const right_address = try input_view.resolveSymbolAddress("compute_right");
    const left_file_offset = try input_view.addressToOffset(left_address);
    const expected_left_bytes = try common.hexStringAlloc(allocator, input_bytes[left_file_offset .. left_file_offset + 4]);
    defer allocator.free(expected_left_bytes);
    const meta_json = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "target": {{
        \\    "arch": "aarch64",
        \\    "os": "linux",
        \\    "binary_format": "elf"
        \\  }},
        \\  "payload": {{
        \\    "object_path": "../payloads/payload.o",
        \\    "object_format": "elf"
        \\  }},
        \\  "hooks": [
        \\    {{
        \\      "kind": "instrument",
        \\      "target": {{
        \\        "kind": "virtual_address",
        \\        "virtual_address": "0x{x}"
        \\      }},
        \\      "handler_symbol": "on_hit",
        \\      "expected_bytes": "{s}",
        \\      "log_message": "zrwrite: meta hit\n"
        \\    }},
        \\    {{
        \\      "kind": "instrument",
        \\      "target": {{
        \\        "kind": "virtual_address",
        \\        "virtual_address": "0x{x}"
        \\      }},
        \\      "handler_symbol": "on_hit",
        \\      "log_message": "zrwrite: meta hit\n"
        \\    }}
        \\  ]
        \\}}
    ,
        .{ left_address, expected_left_bytes, right_address },
    );
    defer allocator.free(meta_json);

    try tmp.dir.writeFile(.{
        .sub_path = "meta/bundle.meta.json",
        .data = meta_json,
    });

    var owned_spec = try zrwrite.bundle.loadBuildSpecFromMetaPath(allocator, meta_path);
    defer owned_spec.deinit();

    const expected_payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "meta", "../payloads/payload.o" });
    defer allocator.free(expected_payload_path);

    try std.testing.expectEqualStrings(expected_payload_path, owned_spec.build_spec.payload_object_path);
    try std.testing.expectEqual(@as(usize, 2), owned_spec.build_spec.hooks.len);
    try std.testing.expectEqualStrings(expected_left_bytes, owned_spec.build_spec.hooks[0].expected_bytes);
    try std.testing.expectEqualStrings("", owned_spec.build_spec.hooks[1].expected_bytes);

    try zrwrite.bundle.writeToPath(allocator, bundle_path, owned_spec.build_spec);
    _ = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);

    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);

    const right_file_offset = try input_view.addressToOffset(right_address);

    const left_branch_opcode = try common.readLeU32(output_bytes, left_file_offset);
    const right_branch_opcode = try common.readLeU32(output_bytes, right_file_offset);
    const left_branch_target = try zrwrite.aarch64.decodeBranchTarget(left_branch_opcode, left_address);
    const right_branch_target = try zrwrite.aarch64.decodeBranchTarget(right_branch_opcode, right_address);

    try std.testing.expect(left_branch_target != right_branch_target);
    try std.testing.expectEqual(2, common.countOccurrences(output_bytes, "zrwrite: meta hit\n"));
}

test "bundle -> apply rejects expected-bytes mismatches with a rewrite diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_expected_bytes.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_expected_bytes.patched" });
    defer allocator.free(output_path);

    try common.runCommand(allocator, &.{
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
        "tests/fixtures/shared/compute.c",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("compute"),
                .handler_symbol = "on_hit",
                .expected_bytes = "ff ff ff ff",
            },
        },
    });

    zrwrite.clearLastRewriteDiagnostic();
    try std.testing.expectError(
        error.ExpectedBytesMismatch,
        zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path),
    );

    const diagnostic = zrwrite.lastRewriteDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "expected-bytes mismatch") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "ffffffff") != null);
}

test "bundle -> apply links Zig payload sections and relocations into instrument hook" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_payload_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_payload_runtime.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_payload_runtime.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_payload_target.patched" });
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
        "tests/fixtures/elf/zig/zig_payload_target.S",
        "tests/fixtures/elf/zig/zig_payload_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-linux-musl",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "-I",
        "include",
        emit_bin_arg,
        "tests/fixtures/elf/zig/zig_payload_runtime.zig",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("zig_payload_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite zig payload hit\n",
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
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite zig payload hit\n") != null);
}

test "bundle -> apply supports public zrwrite + zrstd imports in Zig payloads" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_zrstd_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_zrstd_runtime.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_zrstd_runtime.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_zrstd_target.patched" });
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
        "tests/fixtures/elf/zig/zig_payload_target.S",
        "tests/fixtures/elf/zig/zig_payload_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-linux-musl",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "--dep",
        "zrwrite",
        "--dep",
        "zrstd",
        "-Mroot=tests/fixtures/elf/zig/zig_zrstd_runtime.zig",
        "-Mzrwrite=src/root.zig",
        "-Mzrstd=src/zrstd/root.zig",
        emit_bin_arg,
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("zig_payload_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite zrstd payload hit\n",
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
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrstd helper hit @0x") != null);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite zrstd payload hit\n") != null);
}

test "bundle -> apply supports executable pattern locators" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_target.patched" });
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
    const target_file_offset = try input_view.addressToOffset(target_address);
    const exact_pattern = try common.hexStringAlloc(allocator, input_bytes[target_file_offset .. target_file_offset + 8]);
    defer allocator.free(exact_pattern);

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
                .target = zrwrite.bundle.HookLocator.fromPattern(exact_pattern, 0),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite pattern locator hit\n",
                .stolen_instruction_count = 2,
            },
        },
    });

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const branch_opcode = try common.readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite pattern locator hit\n") != null);
}

test "bundle -> apply rejects non-unique executable pattern locators with a diagnostic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_ambiguous_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_ambiguous_payload.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_ambiguous_payload.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "pattern_ambiguous_target.patched" });
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
        "tests/fixtures/shared/compute.c",
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
                .target = zrwrite.bundle.HookLocator.fromPattern("c0035fd6", 0),
                .handler_symbol = "on_hit",
            },
        },
    });

    zrwrite.clearLastRewriteDiagnostic();
    try std.testing.expectError(
        error.PatternNotUnique,
        zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path),
    );
    const diagnostic = zrwrite.lastRewriteDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "pattern locator matched multiple") != null);
}

test "bundle -> apply resolves external target symbols for Zig payload calls" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_call_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_call_runtime.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_call_runtime.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_call_target.patched" });
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
        "tests/fixtures/elf/zig/zig_external_call_target.S",
        "tests/fixtures/elf/zig/zig_external_call_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-linux-musl",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "-I",
        "include",
        emit_bin_arg,
        "tests/fixtures/elf/zig/zig_external_call_runtime.zig",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("zig_external_call_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite zig external call hit\n",
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
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite zig external call hit\n") != null);
}

test "bundle -> apply resolves external target data symbols for Zig payload loads" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_runtime.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_runtime.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_target.patched" });
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
        "tests/fixtures/elf/zig/zig_external_data_target.S",
        "tests/fixtures/elf/zig/zig_external_data_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-linux-musl",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "-I",
        "include",
        emit_bin_arg,
        "tests/fixtures/elf/zig/zig_external_data_runtime.zig",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("zig_external_data_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite zig external data hit\n",
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
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite zig external data hit\n") != null);
}

test "bundle -> apply supports composite Zig payload with external data, external call, and internal bss" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_composite_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_composite_runtime.o" });
    defer allocator.free(payload_path);
    const bundle_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_composite_runtime.zrpb" });
    defer allocator.free(bundle_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_composite_target.patched" });
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
        "tests/fixtures/elf/zig/zig_composite_target.S",
        "tests/fixtures/elf/zig/zig_composite_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try common.runCommand(allocator, &.{
        "zig",
        "build-obj",
        "-target",
        "aarch64-linux-musl",
        "-O",
        "ReleaseSmall",
        "-fstrip",
        "-I",
        "include",
        emit_bin_arg,
        "tests/fixtures/elf/zig/zig_composite_runtime.zig",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("zig_composite_patchpoint"),
                .handler_symbol = "on_hit",
                .log_message = "zrwrite zig composite hit\n",
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
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite zig composite hit\n") != null);
}
