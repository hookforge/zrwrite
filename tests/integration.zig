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
        "tests/fixtures/compute_pair.c",
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

    const left_branch_opcode = try readLeU32(output_bytes, left_file_offset);
    const right_branch_opcode = try readLeU32(output_bytes, right_file_offset);
    const left_branch_target = try zrwrite.aarch64.decodeBranchTarget(left_branch_opcode, left_address);
    const right_branch_target = try zrwrite.aarch64.decodeBranchTarget(right_branch_opcode, right_address);

    try std.testing.expect(left_branch_target != right_branch_target);
    try std.testing.expect(left_branch_target > left_address);
    try std.testing.expect(right_branch_target > right_address);
    try std.testing.expectEqual(report.stub_address.?, right_branch_target);
    try std.testing.expectEqual(2, countOccurrences(output_bytes, "zrwrite: pair hit\n"));
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
        "tests/fixtures/compute_pair.c",
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

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const left_address = try input_view.resolveSymbolAddress("compute_left");
    const right_address = try input_view.resolveSymbolAddress("compute_right");
    const left_file_offset = try input_view.addressToOffset(left_address);
    const expected_left_bytes = try hexStringAlloc(allocator, input_bytes[left_file_offset .. left_file_offset + 4]);
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

    const left_branch_opcode = try readLeU32(output_bytes, left_file_offset);
    const right_branch_opcode = try readLeU32(output_bytes, right_file_offset);
    const left_branch_target = try zrwrite.aarch64.decodeBranchTarget(left_branch_opcode, left_address);
    const right_branch_target = try zrwrite.aarch64.decodeBranchTarget(right_branch_opcode, right_address);

    try std.testing.expect(left_branch_target != right_branch_target);
    try std.testing.expectEqual(2, countOccurrences(output_bytes, "zrwrite: meta hit\n"));
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
        "tests/fixtures/zig_payload_target.S",
        "tests/fixtures/zig_payload_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_payload_runtime.zig",
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
        "tests/fixtures/zig_payload_target.S",
        "tests/fixtures/zig_payload_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "-Mroot=tests/fixtures/zig_zrstd_runtime.zig",
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
        "tests/fixtures/wide_window_target.S",
        "tests/fixtures/wide_window_main.c",
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
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try readLeU32(output_bytes, target_file_offset + 4));
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try readLeU32(output_bytes, target_file_offset + 8));
    try std.testing.expectEqual(zrwrite.aarch64.nop_instruction, try readLeU32(output_bytes, target_file_offset + 12));
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
        "tests/fixtures/wide_semantic_adrp_target.S",
        "tests/fixtures/wide_semantic_adrp_main.c",
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
    const branch_opcode = try readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try readLeU32(output_bytes, target_file_offset + 4),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try readLeU32(output_bytes, target_file_offset + 8),
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
        "tests/fixtures/terminal_branch_target.S",
        "tests/fixtures/terminal_branch_main.c",
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
    const branch_opcode = try readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try readLeU32(output_bytes, target_file_offset + 4),
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/terminal_branch_o2.c",
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
    const branch_opcode = try readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expectEqual(@as(?u64, null), report.trampoline_address);
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite O2 terminal branch replay hit\n") != null);
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/terminal_branch_o2.c",
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

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const target_address = try input_view.resolveSymbolAddress("stripped_terminal_branch");
    const target_file_offset = try input_view.addressToOffset(target_address);
    const exact_pattern = try hexStringAlloc(allocator, input_bytes[target_file_offset .. target_file_offset + 8]);
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
    const branch_opcode = try readLeU32(output_bytes, target_file_offset);
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
        "tests/fixtures/wide_window8_target.S",
        "tests/fixtures/wide_window8_main.c",
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
    const branch_opcode = try readLeU32(output_bytes, target_file_offset);
    const branch_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, target_address);

    try std.testing.expectEqual(report.stub_address.?, branch_target);
    try std.testing.expect(report.trampoline_address != null);
    for (1..8) |index| {
        try std.testing.expectEqual(
            zrwrite.aarch64.nop_instruction,
            try readLeU32(output_bytes, target_file_offset + index * 4),
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
        "tests/fixtures/wide_window_branch_target.S",
        "tests/fixtures/wide_window_branch_main.c",
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
    const retargeted_opcode = try readLeU32(output_bytes, branch_source_file_offset);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(retargeted_opcode, branch_source_address);
    const trampoline_file_offset = try output_view.addressToOffset(report.trampoline_address.?);

    try std.testing.expectEqual(
        report.trampoline_address.? + 4,
        retargeted_target,
    );
    try std.testing.expectEqual(
        try readLeU32(output_bytes, trampoline_file_offset + 4),
        try readLeU32(input_bytes, try input_view.addressToOffset(try input_view.resolveSymbolAddress("wide_branch_mid"))),
    );
}

test "bundle -> apply still rejects incoming branches into semantic-only interior steps" {
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
        "tests/fixtures/terminal_branch_interior_target.S",
        "tests/fixtures/terminal_branch_interior_main.c",
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
                .target = zrwrite.bundle.HookLocator.fromSymbol("terminal_branch_interior_patchpoint"),
                .handler_symbol = "on_hit",
                .stolen_instruction_count = 2,
            },
        },
    });

    try std.testing.expectError(
        error.IncomingBranchIntoPatchWindow,
        zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path),
    );
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
        "tests/fixtures/wide_semantic_branch_target.S",
        "tests/fixtures/wide_semantic_branch_main.c",
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
    const branch_opcode = try readLeU32(output_bytes, branch_source_file_offset + 4);
    const retargeted_target = try zrwrite.aarch64.decodeBranchTarget(branch_opcode, branch_source_address + 4);

    try std.testing.expectEqual(
        report.trampoline_address.? + 4,
        retargeted_target,
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite semantic interior hit\n") != null);
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
        "tests/fixtures/far_detour_target.S",
        "tests/fixtures/far_detour_main.c",
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
        "tests/fixtures/bti_far_detour_target.S",
        "tests/fixtures/bti_far_detour_main.c",
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
        try readLeU32(output_bytes, stub_file_offset),
    );
    try std.testing.expectEqual(
        zrwrite.aarch64.bti_jc_instruction,
        try readLeU32(output_bytes, trampoline_file_offset),
    );
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
        "tests/fixtures/zig_external_call_target.S",
        "tests/fixtures/zig_external_call_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_external_call_runtime.zig",
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
        "tests/fixtures/zig_external_data_target.S",
        "tests/fixtures/zig_external_data_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_external_data_runtime.zig",
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

test "payload linker rejects GOT-style external data relocations for ET_DYN targets" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_target_pie" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "zig_external_data_runtime.o" });
    defer allocator.free(payload_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-O0",
        "-g0",
        "-fPIE",
        "-pie",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/zig_external_data_target.S",
        "tests/fixtures/zig_external_data_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_external_data_runtime.zig",
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const target_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    try std.testing.expectEqual(std.elf.ET.DYN, target_view.ehdr.e_type);

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    zrwrite.clearLastLinkDiagnostic();
    try std.testing.expectError(
        error.UnsupportedPayloadRelocation,
        zrwrite.payload.linkObjectBytes(allocator, payload_bytes, "on_hit", 0x7000_0000, target_view),
    );

    const diagnostic = zrwrite.lastLinkDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "ADR_GOT_PAGE") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "target_value") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "ET_DYN") != null);
}

test "payload mini-linker patches cross-section CONDBR19 relocations" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    cmp x0, x0
        \\    b.eq helper
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper,"ax",@progbits
        \\.p2align 2
        \\.global helper
        \\.type helper,%function
        \\helper:
        \\    ret
        \\.size helper, .-helper
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "condbr_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x4000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    try std.testing.expectEqual(@as(usize, 0), loaded.entry_offset);

    const branch_opcode = try readLeU32(loaded.image, 4);
    const branch_target = try decodePcRelativeTarget(branch_opcode, image_base_address + 4, 19);
    try std.testing.expectEqual(image_base_address + 12, branch_target);
}

test "payload mini-linker patches cross-section TSTBR14 relocations" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    tbz x0, #1, helper
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper,"ax",@progbits
        \\.p2align 2
        \\.global helper
        \\.type helper,%function
        \\helper:
        \\    ret
        \\.size helper, .-helper
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "tstbr_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x5000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    try std.testing.expectEqual(@as(usize, 0), loaded.entry_offset);

    const branch_opcode = try readLeU32(loaded.image, 0);
    const branch_target = try decodePcRelativeTarget(branch_opcode, image_base_address, 14);
    try std.testing.expectEqual(image_base_address + 8, branch_target);
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
        "tests/fixtures/zig_composite_target.S",
        "tests/fixtures/zig_composite_main.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_composite_runtime.zig",
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

test "payload mini-linker patches MOVW_UABS relocation sequences" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    movz x0, #:abs_g3:helper
        \\    movk x0, #:abs_g2_nc:helper
        \\    movk x0, #:abs_g1_nc:helper
        \\    movk x0, #:abs_g0_nc:helper
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper,"ax",@progbits
        \\.p2align 2
        \\.global helper
        \\.type helper,%function
        \\helper:
        \\    ret
        \\.size helper, .-helper
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "movw_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const g3 = extractMovWideImmediate(try readLeU32(loaded.image, 0));
    const g2 = extractMovWideImmediate(try readLeU32(loaded.image, 4));
    const g1 = extractMovWideImmediate(try readLeU32(loaded.image, 8));
    const g0 = extractMovWideImmediate(try readLeU32(loaded.image, 12));
    const materialized_address = (@as(u64, g3) << 48) |
        (@as(u64, g2) << 32) |
        (@as(u64, g1) << 16) |
        @as(u64, g0);

    try std.testing.expectEqual(image_base_address + 20, materialized_address);
}

test "payload linker stores unsupported relocation diagnostics with relocation and symbol names" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    movz x0, #:prel_g0:helper
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper,"ax",@progbits
        \\.p2align 2
        \\.global helper
        \\.type helper,%function
        \\helper:
        \\    ret
        \\.size helper, .-helper
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "unsupported_prel_movw.S", source);
    defer allocator.free(object_bytes);

    zrwrite.clearLastLinkDiagnostic();
    try std.testing.expectError(
        error.UnsupportedPayloadRelocation,
        zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x7000_0000, null),
    );

    const diagnostic = zrwrite.lastLinkDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "MOVW_PREL_G0") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "helper") != null);
}

fn compileAarch64AssemblyObject(
    allocator: std.mem.Allocator,
    source_name: []const u8,
    source: []const u8,
) ![]u8 {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = source_name,
        .data = source,
    });

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const source_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, source_name });
    defer allocator.free(source_path);

    const object_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "payload.o" });
    defer allocator.free(object_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-linux-musl",
        "-c",
        "-g0",
        "-fPIC",
        "-fno-stack-protector",
        "-fno-sanitize=undefined",
        "-fno-asynchronous-unwind-tables",
        source_path,
        "-o",
        object_path,
    });

    return std.fs.cwd().readFileAlloc(allocator, object_path, std.math.maxInt(usize));
}

fn readLeU32(bytes: []const u8, offset: usize) !u32 {
    if (offset + @sizeOf(u32) > bytes.len) return error.EndOfStream;
    const ptr: *const [4]u8 = @ptrCast(bytes[offset .. offset + 4].ptr);
    return std.mem.readInt(u32, ptr, .little);
}

fn hexStringAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    errdefer allocator.free(out);

    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 0xF];
    }
    return out;
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;

    var count: usize = 0;
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, cursor, needle)) |index| {
        count += 1;
        cursor = index + needle.len;
    }
    return count;
}

fn extractMovWideImmediate(opcode: u32) u16 {
    return @intCast((opcode >> 5) & 0xFFFF);
}

fn decodePcRelativeTarget(opcode: u32, site_address: u64, imm_bits: u6) !u64 {
    const imm = switch (imm_bits) {
        19 => (opcode >> 5) & 0x7FFFF,
        14 => (opcode >> 5) & 0x3FFF,
        else => return error.UnsupportedImmediateWidth,
    };
    const delta = try decodeSignedScaledImmediate(imm, imm_bits, 2);
    const result = @as(i128, @intCast(site_address)) + @as(i128, delta);
    if (result < 0 or result > std.math.maxInt(u64)) return error.Overflow;
    return @intCast(result);
}

fn decodeSignedScaledImmediate(raw: u32, bits: u6, shift: u6) !i64 {
    const shift_amount: u5 = @intCast(bits - 1);
    const bits_shift: u5 = @intCast(bits);
    const sign_bit = @as(u32, 1) << shift_amount;
    const extended = if ((raw & sign_bit) != 0)
        raw | ~((@as(u32, 1) << bits_shift) - 1)
    else
        raw;
    const signed: i32 = @bitCast(extended);
    const result = @as(i128, signed) << shift;
    if (result < std.math.minInt(i64) or result > std.math.maxInt(i64)) return error.Overflow;
    return @intCast(result);
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
