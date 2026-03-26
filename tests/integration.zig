const builtin = @import("builtin");
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

test "image backend parses thin arm64 Mach-O executables on macOS hosts" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho" });
    defer allocator.free(input_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);

    const backend_view = try zrwrite.image_backend.View.parseAs(@constCast(input_bytes), .macho);
    try std.testing.expectEqual(zrwrite.bundle.BinaryFormat.macho, backend_view.binaryFormat());

    const main_address = try backend_view.resolveSymbolAddress("main");
    const underscored_main_address = try backend_view.resolveSymbolAddress("_main");
    try std.testing.expectEqual(main_address, underscored_main_address);

    const main_offset = try backend_view.addressToOffset(main_address);
    try std.testing.expectEqual(main_address, try backend_view.offsetToAddress(main_offset));

    const compute_address = try backend_view.resolveSymbolAddress("compute");
    try std.testing.expect(compute_address != 0);

    const executable_ranges = try backend_view.executableRanges(allocator);
    defer allocator.free(executable_ranges);
    try std.testing.expect(executable_ranges.len != 0);
}

test "Mach-O view plans linkedit-tail injection and can clear stale code signatures" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_layout" });
    defer allocator.free(input_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    const original_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(original_bytes);

    const mutable_bytes = try allocator.dupe(u8, original_bytes);
    defer allocator.free(mutable_bytes);

    const view = try zrwrite.format.macho.View.parse(mutable_bytes);
    const carrier = try view.carrierSegmentForInjection();
    const linkedit = try view.segmentByName("__LINKEDIT");
    const original_linkedit_fileoff = linkedit.command.fileoff;
    const original_linkedit_vmaddr = linkedit.command.vmaddr;
    const original_symtab = (try view.symbolTableRange()).?;
    const original_strtab = (try view.stringTableRange()).?;
    const original_code_signature = (try view.codeSignatureRange()).?;
    const carrier_end = std.mem.alignForward(usize, try view.segmentUsedEndFileOffset(carrier), 16);
    const slack_before_linkedit = @as(usize, @intCast(original_linkedit_fileoff)) - carrier_end;
    const plan = try view.planInjection(slack_before_linkedit + 0x100, 16);

    try std.testing.expectEqual(@as(usize, 0x4000), plan.tail_shift);
    try std.testing.expect(!plan.fitsExistingSlack());
    try std.testing.expectEqual(original_bytes.len + plan.tail_shift, plan.total_len);

    const output_bytes = try view.materializeInjectedImage(allocator, plan);
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(output_bytes);
    const final_size = try output_view.finalizeInjectedImage(plan, true);
    try std.testing.expectEqual(output_bytes.len - original_code_signature.size, final_size);

    const finalized_view = try zrwrite.format.macho.View.parse(output_bytes[0..final_size]);
    const output_carrier = try finalized_view.segmentByName(carrier.segName());
    try std.testing.expectEqual(plan.injection_end_offset - @as(usize, @intCast(carrier.command.fileoff)), output_carrier.command.filesize);
    try std.testing.expectEqual(output_carrier.command.filesize, output_carrier.command.vmsize);
    try std.testing.expect((output_carrier.command.initprot & std.macho.PROT.EXEC) != 0);
    try std.testing.expect((output_carrier.command.maxprot & std.macho.PROT.EXEC) != 0);

    const shifted_linkedit = try finalized_view.segmentByName("__LINKEDIT");
    try std.testing.expectEqual(original_linkedit_fileoff + plan.tail_shift, shifted_linkedit.command.fileoff);
    try std.testing.expectEqual(original_linkedit_vmaddr + plan.tail_shift, shifted_linkedit.command.vmaddr);
    try std.testing.expectEqual(@as(u64, 0), shifted_linkedit.command.fileoff % 0x4000);
    try std.testing.expectEqual(@as(u64, 0), shifted_linkedit.command.vmaddr % 0x4000);
    try std.testing.expectEqual(original_symtab.offset + plan.tail_shift, (try finalized_view.symbolTableRange()).?.offset);
    try std.testing.expectEqual(original_strtab.offset + plan.tail_shift, (try finalized_view.stringTableRange()).?.offset);
    try std.testing.expectEqual(@as(u64, @intCast(final_size)), shifted_linkedit.command.fileoff + shifted_linkedit.command.filesize);
    try std.testing.expect((try finalized_view.codeSignatureRange()) == null);
}

test "Mach-O executable injection preserves text references into shifted data segments" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_shifted_data_ref" });
    defer allocator.free(input_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_shifted_data_ref.shifted" });
    defer allocator.free(output_path);

    try runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-Wl,-e,_main",
        "tests/fixtures/macho_shifted_data_ref.S",
        "-o",
        input_path,
    });

    const original_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(original_bytes);

    const mutable_bytes = try allocator.dupe(u8, original_bytes);
    defer allocator.free(mutable_bytes);

    const view = try zrwrite.format.macho.View.parse(mutable_bytes);
    const split_plan = try view.planCarrierSplitInjection(0x5000, 0, 16);
    try std.testing.expect(!split_plan.executable.fitsExistingSlack());

    const output_bytes = try view.materializeSplitInjectedImage(allocator, split_plan);
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(output_bytes);
    const final_size = try output_view.finalizeSplitInjectedImage(split_plan);
    try std.fs.cwd().writeFile(.{
        .sub_path = output_path,
        .data = output_bytes[0..final_size],
    });

    try runCommand(allocator, &.{ "chmod", "+x", output_path });
    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 7);
}

test "Mach-O segment shifting preserves Objective-C relative method metadata" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_objc_methodlist" });
    defer allocator.free(input_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_objc_methodlist.shifted" });
    defer allocator.free(output_path);

    try runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fobjc-arc",
        "tests/fixtures/macho_objc_methodlist.m",
        "-framework",
        "Foundation",
        "-o",
        input_path,
    });

    const original_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(original_bytes);

    const mutable_bytes = try allocator.dupe(u8, original_bytes);
    defer allocator.free(mutable_bytes);

    const view = try zrwrite.format.macho.View.parse(mutable_bytes);
    const split_plan = try view.planCarrierSplitInjection(0x5000, 0, 16);
    try std.testing.expect(!split_plan.executable.fitsExistingSlack());

    const output_bytes = try view.materializeSplitInjectedImage(allocator, split_plan);
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(output_bytes);
    const final_size = try output_view.finalizeSplitInjectedImage(split_plan);
    try std.fs.cwd().writeFile(.{
        .sub_path = output_path,
        .data = output_bytes[0..final_size],
    });

    try runCommand(allocator, &.{ "chmod", "+x", output_path });
    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 7);

    const objc_info = try runCommandCaptureStdout(allocator, &.{ "xcrun", "dyld_info", "-objc", output_path });
    defer allocator.free(objc_info);
    try std.testing.expect(std.mem.indexOf(u8, objc_info, "-[ArMethodListDemo answer]") != null);
}

test "Mach-O split injection with writable payload keeps Objective-C chained fixups parseable" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_objc_methodlist_split" });
    defer allocator.free(input_path);
    const output_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_objc_methodlist_split.shifted" });
    defer allocator.free(output_path);

    try runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fobjc-arc",
        "tests/fixtures/macho_objc_methodlist.m",
        "-framework",
        "Foundation",
        "-o",
        input_path,
    });

    const original_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(original_bytes);

    const mutable_bytes = try allocator.dupe(u8, original_bytes);
    defer allocator.free(mutable_bytes);

    const view = try zrwrite.format.macho.View.parse(mutable_bytes);
    const split_plan = try view.planCarrierSplitInjection(0x5000, 0x2000, 16);
    try std.testing.expect(split_plan.hasWritableRegion());
    try std.testing.expect(!split_plan.executable.fitsExistingSlack());

    const output_bytes = try view.materializeSplitInjectedImage(allocator, split_plan);
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(output_bytes);
    const final_size = try output_view.finalizeSplitInjectedImage(split_plan);
    try std.fs.cwd().writeFile(.{
        .sub_path = output_path,
        .data = output_bytes[0..final_size],
    });

    try runCommand(allocator, &.{ "chmod", "+x", output_path });
    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 7);

    const objc_info = try runCommandCaptureStdout(allocator, &.{ "xcrun", "dyld_info", "-objc", output_path });
    defer allocator.free(objc_info);
    try std.testing.expect(std.mem.indexOf(u8, objc_info, "-[ArMethodListDemo answer]") != null);
}

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

    try runCommand(allocator, &.{
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
        "tests/fixtures/compute_stateful.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_payload_stateful.c",
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_replace_branch_payload.c",
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

test "Mach-O finalize emits a diagnostic when codesign-safe LINKEDIT closure is impossible" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "compute_macho_diag" });
    defer allocator.free(input_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    const original_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(original_bytes);

    const mutable_bytes = try allocator.dupe(u8, original_bytes);
    defer allocator.free(mutable_bytes);

    const view = try zrwrite.format.macho.View.parse(mutable_bytes);
    const carrier = try view.carrierSegmentForInjection();
    const linkedit = try view.segmentByName("__LINKEDIT");
    const carrier_end = std.mem.alignForward(
        usize,
        @as(usize, @intCast(carrier.command.fileoff + @max(carrier.command.filesize, carrier.command.vmsize))),
        16,
    );
    const slack_before_linkedit = @as(usize, @intCast(linkedit.command.fileoff)) - carrier_end;
    const plan = try view.planInjection(slack_before_linkedit + 0x100, 16);

    const output_bytes = try view.materializeInjectedImage(allocator, plan);
    defer allocator.free(output_bytes);

    const output_view = try zrwrite.format.macho.View.parse(output_bytes);
    const broken_linkedit = try output_view.segmentByName("__LINKEDIT");
    broken_linkedit.command.filesize -= 4;

    try std.testing.expectError(error.UnsafeMachOCodeSignatureLayout, output_view.finalizeInjectedImage(plan, true));
    const diagnostic = zrwrite.format.macho.lastDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "__LINKEDIT ends") != null);
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

    try runCommand(allocator, &.{
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
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_payload_runtime.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 53);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_payload_stateful.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 53);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute_stateful.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_payload_large_stateful.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 34);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute_pair.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_multi_handler_shared_state_payload.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 32);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "-Mroot=tests/fixtures/macho_zrstd_multi_default_runtime.zig",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });

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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "-Mroot=tests/fixtures/macho_zrstd_stderr_runtime.zig",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });

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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/compute.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_replace_branch_payload.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 63);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho_external_data_patchpoint.S",
        "tests/fixtures/macho_external_data_target.c",
        "-o",
        input_path,
    });

    const emit_bin_arg = try std.fmt.allocPrint(allocator, "-femit-bin={s}", .{payload_path});
    defer allocator.free(emit_bin_arg);

    try runCommand(allocator, &.{
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
        "tests/fixtures/zig_external_data_runtime.zig",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 0);
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

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho_external_data_patchpoint.S",
        "tests/fixtures/macho_external_data_target.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
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
        "tests/fixtures/macho_internal_pointer_payload.c",
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

    try runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try runCommandExpectExitCode(allocator, &.{output_path}, 0);
}

test "Mach-O payload linker keeps explicit PIE diagnostics for read-only absolute pointers" {
    if (builtin.os.tag != .macos or builtin.cpu.arch != .aarch64) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_dir_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_dir_path);

    const input_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_readonly_pointer_target" });
    defer allocator.free(input_path);
    const payload_path = try std.fs.path.join(allocator, &.{ tmp_dir_path, "macho_readonly_pointer_payload.o" });
    defer allocator.free(payload_path);

    try runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "-fno-sanitize=undefined",
        "-fno-stack-protector",
        "-fno-asynchronous-unwind-tables",
        "tests/fixtures/macho_external_data_patchpoint.S",
        "tests/fixtures/macho_external_data_target.c",
        "-o",
        input_path,
    });

    try runCommand(allocator, &.{
        "clang",
        "-target",
        "arm64-apple-macos11",
        "-c",
        "tests/fixtures/macho_readonly_pointer_payload.S",
        "-o",
        payload_path,
    });

    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const target_view = try zrwrite.format.macho.View.parse(@constCast(input_bytes));
    try std.testing.expect(target_view.isPie());

    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, payload_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);

    zrwrite.clearLastLinkDiagnostic();
    try std.testing.expectError(
        error.UnsupportedPayloadRelocation,
        zrwrite.payload.linkObjectBytesForFormatWithImageBases(
            allocator,
            .macho,
            payload_bytes,
            "on_hit",
            .{
                .primary = 0x1_0000_0000,
                .writable = 0x1_0001_0000,
            },
            .{ .macho = target_view },
        ),
    );

    const diagnostic = zrwrite.lastLinkDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "ARM64_RELOC_UNSIGNED") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "local_value") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "primary read-only payload image") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "unable to apply Mach-O arm64 payload relocation") == null);
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
        "tests/fixtures/add_terminal_branch_target.S",
        "tests/fixtures/add_terminal_branch_main.c",
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
    try std.testing.expectEqual(
        zrwrite.aarch64.nop_instruction,
        try readLeU32(output_bytes, target_file_offset + 12),
    );
    try std.testing.expect(std.mem.indexOf(u8, output_bytes, "zrwrite add terminal branch replay hit\n") != null);
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

    const report = try zrwrite.apply.applyBundleFileToPath(allocator, bundle_path, input_path, output_path);
    const output_bytes = try std.fs.cwd().readFileAlloc(allocator, output_path, std.math.maxInt(usize));
    defer allocator.free(output_bytes);
    const input_bytes = try std.fs.cwd().readFileAlloc(allocator, input_path, std.math.maxInt(usize));
    defer allocator.free(input_bytes);
    const input_view = try zrwrite.elf.View.parse(@constCast(input_bytes));
    const branch_source_address = try input_view.resolveSymbolAddress("branch_to_terminal_branch_mid");
    const branch_source_file_offset = try input_view.addressToOffset(branch_source_address);
    const retargeted_opcode = try readLeU32(output_bytes, branch_source_file_offset);
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
        "tests/fixtures/semantic_prefix_interior_target.S",
        "tests/fixtures/semantic_prefix_interior_main.c",
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
    const retargeted_opcode = try readLeU32(output_bytes, branch_source_file_offset);
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
        "tests/fixtures/unsupported_semantic_interior_target.S",
        "tests/fixtures/unsupported_semantic_interior_main.c",
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
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "synthetic GOT slot") != null);
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

test "payload mini-linker patches MOVW_PREL relocation sequences" {
    const allocator = std.testing.allocator;

    const source =
        \\.section .text.helper,"ax",@progbits
        \\.p2align 2
        \\.global helper
        \\.type helper,%function
        \\helper:
        \\    ret
        \\.size helper, .-helper
        \\
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    movz x0, #:prel_g0:helper
        \\    movk x1, #:prel_g1_nc:helper
        \\    movk x2, #:prel_g2_nc:helper
        \\    movk x3, #:prel_g3:helper
        \\    ret
        \\.size on_hit, .-on_hit
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "movw_prel_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6100_0000;
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const helper_address = image_base_address + helper_layout.entry_offset;
    const on_hit_address = image_base_address + loaded.entry_offset;

    const opcode0 = try readLeU32(loaded.image, loaded.entry_offset + 0);
    const opcode1 = try readLeU32(loaded.image, loaded.entry_offset + 4);
    const opcode2 = try readLeU32(loaded.image, loaded.entry_offset + 8);
    const opcode3 = try readLeU32(loaded.image, loaded.entry_offset + 12);

    const delta0: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 0)));
    const delta1: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 4)));
    const delta2: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 8)));
    const delta3: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 12)));

    try std.testing.expectEqual(@as(u2, if (delta0 < 0) 0 else 2), extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode2));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode3));

    try std.testing.expectEqual(expectedSignedMoveWideImmediate(delta0, 0, delta0 < 0), extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(delta1, 16, false), extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(delta2, 32, false), extractMovWideImmediate(opcode2));
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(delta3, 48, false), extractMovWideImmediate(opcode3));
}

test "payload mini-linker patches MOVW_SABS relocation sequences" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    movz x0, #:abs_g0_s:helper
        \\    movz x1, #:abs_g1_s:helper
        \\    movz x2, #:abs_g2_s:helper
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

    const object_bytes = try compileAarch64AssemblyObject(allocator, "movw_sabs_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x1000;
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const helper_address = image_base_address + helper_layout.entry_offset;

    const opcode0 = try readLeU32(loaded.image, 0);
    const opcode1 = try readLeU32(loaded.image, 4);
    const opcode2 = try readLeU32(loaded.image, 8);

    try std.testing.expectEqual(@as(u2, 2), extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 2), extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 2), extractMoveWideOpcode(opcode2));

    const signed_helper: i64 = @intCast(helper_address);
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(signed_helper, 0, false), extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(signed_helper, 16, false), extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(expectedSignedMoveWideImmediate(signed_helper, 32, false), extractMovWideImmediate(opcode2));
}

test "payload mini-linker patches GOT_LD_PREL19 relocations through synthetic GOT slots" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    ldr x0, :got:helper
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

    const object_bytes = try compileAarch64AssemblyObject(allocator, "got_ld_prel19_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6300_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const slot_address = image_base_address + layout.image_size - @sizeOf(u64);
    const ldr_opcode = try readLeU32(loaded.image, 0);
    const literal_target = try decodePcRelativeTarget(ldr_opcode, image_base_address, 19);

    try std.testing.expectEqual(slot_address, literal_target);
    try std.testing.expectEqual(image_base_address + helper_layout.entry_offset, try readLeU64(loaded.image, layout.image_size - @sizeOf(u64)));
}

test "payload mini-linker patches LD64_GOTPAGE_LO15 relocations through synthetic GOT slots" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    adrp x0, _GLOBAL_OFFSET_TABLE_
        \\    ldr x0, [x0, #:gotpage_lo15:helper]
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

    const object_bytes = try compileAarch64AssemblyObject(allocator, "gotpage_lo15_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6400_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const slot_address = image_base_address + layout.image_size - @sizeOf(u64);
    const adrp_opcode = try readLeU32(loaded.image, 0);
    const ldr_opcode = try readLeU32(loaded.image, 4);

    const slot_page = try decodeAdrpPageTarget(adrp_opcode, image_base_address);
    const slot_offset = extractUnsignedLoadStoreImmediate(ldr_opcode, 3);

    try std.testing.expectEqual(slot_address & ~@as(u64, 0xFFF), slot_page);
    try std.testing.expectEqual(slot_address, slot_page + slot_offset);
    try std.testing.expectEqual(image_base_address + helper_layout.entry_offset, try readLeU64(loaded.image, layout.image_size - @sizeOf(u64)));
}

test "payload mini-linker patches GOTREL64 and GOTREL32 relocations against the synthetic GOT base" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 3
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    .xword helper
        \\    .word helper
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

    const object_bytes = try compileAarch64AssemblyObject(allocator, "gotrel_payload.S", source);
    defer allocator.free(object_bytes);

    try overwriteRelaTypeAtIndex(object_bytes, 0, @intFromEnum(std.elf.R_AARCH64.GOTREL64));
    try overwriteRelaTypeAtIndex(object_bytes, 1, @intFromEnum(std.elf.R_AARCH64.GOTREL32));

    const image_base_address: u64 = 0x6500_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const got_base_address = image_base_address + layout.image_size;
    const helper_address = image_base_address + helper_layout.entry_offset;
    const expected_delta: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(got_base_address)));

    try std.testing.expectEqual(expected_delta, try readLeI64(loaded.image, loaded.entry_offset + 0));
    try std.testing.expectEqual(@as(i32, @intCast(expected_delta)), try readLeI32(loaded.image, loaded.entry_offset + 8));
}

test "payload mini-linker patches MOVW_GOTOFF relocation sequences through synthetic GOT slots" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    ldr x9, :got:helper0
        \\    movz x0, #:prel_g0:helper1
        \\    movk x1, #:prel_g1_nc:helper1
        \\    movk x2, #:prel_g2_nc:helper1
        \\    movk x3, #:prel_g3:helper1
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper0,"ax",@progbits
        \\.p2align 2
        \\.global helper0
        \\.type helper0,%function
        \\helper0:
        \\    ret
        \\.size helper0, .-helper0
        \\
        \\.section .text.helper1,"ax",@progbits
        \\.p2align 2
        \\.global helper1
        \\.type helper1,%function
        \\helper1:
        \\    ret
        \\.size helper1, .-helper1
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "movw_gotoff_payload.S", source);
    defer allocator.free(object_bytes);

    try overwriteRelaTypeAtIndex(object_bytes, 1, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G0));
    try overwriteRelaTypeAtIndex(object_bytes, 2, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G1_NC));
    try overwriteRelaTypeAtIndex(object_bytes, 3, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G2_NC));
    try overwriteRelaTypeAtIndex(object_bytes, 4, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G3));

    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x6600_0000, null);
    defer allocator.free(loaded.image);

    const opcode0 = try readLeU32(loaded.image, loaded.entry_offset + 4);
    const opcode1 = try readLeU32(loaded.image, loaded.entry_offset + 8);
    const opcode2 = try readLeU32(loaded.image, loaded.entry_offset + 12);
    const opcode3 = try readLeU32(loaded.image, loaded.entry_offset + 16);

    try std.testing.expectEqual(@as(u2, 2), extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode2));
    try std.testing.expectEqual(@as(u2, 3), extractMoveWideOpcode(opcode3));

    try std.testing.expectEqual(@as(u16, 8), extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(@as(u16, 0), extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(@as(u16, 0), extractMovWideImmediate(opcode2));
    try std.testing.expectEqual(@as(u16, 0), extractMovWideImmediate(opcode3));
}

test "payload mini-linker patches LD64_GOTOFF_LO15 relocations through synthetic GOT slots" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    ldr x9, :got:helper0
        \\    adrp x0, _GLOBAL_OFFSET_TABLE_
        \\    add x0, x0, #:lo12:_GLOBAL_OFFSET_TABLE_
        \\    ldr x0, [x0, #:gotpage_lo15:helper1]
        \\    ret
        \\.size on_hit, .-on_hit
        \\
        \\.section .text.helper0,"ax",@progbits
        \\.p2align 2
        \\.global helper0
        \\.type helper0,%function
        \\helper0:
        \\    ret
        \\.size helper0, .-helper0
        \\
        \\.section .text.helper1,"ax",@progbits
        \\.p2align 2
        \\.global helper1
        \\.type helper1,%function
        \\helper1:
        \\    ret
        \\.size helper1, .-helper1
        \\
    ;

    const object_bytes = try compileAarch64AssemblyObject(allocator, "gotoff_lo15_payload.S", source);
    defer allocator.free(object_bytes);

    try overwriteRelaTypeAtIndex(object_bytes, 3, @intFromEnum(std.elf.R_AARCH64.LD64_GOTOFF_LO15));

    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x6700_0000, null);
    defer allocator.free(loaded.image);

    const ldr_opcode = try readLeU32(loaded.image, loaded.entry_offset + 12);
    try std.testing.expectEqual(@as(u64, 8), extractUnsignedLoadStoreImmediate(ldr_opcode, 3));
}

test "payload linker stores unsupported relocation diagnostics with relocation and symbol names" {
    const allocator = std.testing.allocator;

    const source =
        \\.text
        \\.p2align 2
        \\.global on_hit
        \\.type on_hit,%function
        \\on_hit:
        \\    ldr x0, :got:helper
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

    const object_bytes = try compileAarch64AssemblyObject(allocator, "unsupported_relocation_payload.S", source);
    defer allocator.free(object_bytes);

    try overwriteFirstRelaType(object_bytes, @intFromEnum(std.elf.R_AARCH64.TLSIE_LD_GOTTPREL_PREL19));

    zrwrite.clearLastLinkDiagnostic();
    try std.testing.expectError(
        error.UnsupportedPayloadRelocation,
        zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x7000_0000, null),
    );

    const diagnostic = zrwrite.lastLinkDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "TLSIE_LD_GOTTPREL_PREL19") != null);
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

fn readLeU64(bytes: []const u8, offset: usize) !u64 {
    if (offset + @sizeOf(u64) > bytes.len) return error.EndOfStream;
    const ptr: *const [8]u8 = @ptrCast(bytes[offset .. offset + 8].ptr);
    return std.mem.readInt(u64, ptr, .little);
}

fn readLeI32(bytes: []const u8, offset: usize) !i32 {
    if (offset + @sizeOf(i32) > bytes.len) return error.EndOfStream;
    const ptr: *const [4]u8 = @ptrCast(bytes[offset .. offset + 4].ptr);
    return std.mem.readInt(i32, ptr, .little);
}

fn readLeI64(bytes: []const u8, offset: usize) !i64 {
    if (offset + @sizeOf(i64) > bytes.len) return error.EndOfStream;
    const ptr: *const [8]u8 = @ptrCast(bytes[offset .. offset + 8].ptr);
    return std.mem.readInt(i64, ptr, .little);
}

fn writeLeU64(bytes: []u8, offset: usize, value: u64) !void {
    if (offset + @sizeOf(u64) > bytes.len) return error.EndOfStream;
    var le = std.mem.nativeToLittle(u64, value);
    @memcpy(bytes[offset .. offset + @sizeOf(u64)], std.mem.asBytes(&le));
}

fn overwriteFirstRelaType(object_bytes: []u8, relocation_type: u32) !void {
    return overwriteRelaTypeAtIndex(object_bytes, 0, relocation_type);
}

fn overwriteRelaTypeAtIndex(object_bytes: []u8, relocation_index: usize, relocation_type: u32) !void {
    const view = try zrwrite.elf.View.parse(object_bytes);
    var seen: usize = 0;

    for (view.shdrs) |shdr| {
        if (shdr.sh_type != std.elf.SHT_RELA or shdr.sh_size == 0) continue;

        if (shdr.sh_entsize != @sizeOf(std.elf.Elf64_Rela)) return error.InvalidRelocationTable;
        const rela_count: usize = @intCast(shdr.sh_size / shdr.sh_entsize);
        const rela_base: usize = @intCast(shdr.sh_offset);

        for (0..rela_count) |local_index| {
            if (seen != relocation_index) {
                seen += 1;
                continue;
            }

            const rela_offset = rela_base + local_index * @sizeOf(std.elf.Elf64_Rela);
            const info_offset = rela_offset + @offsetOf(std.elf.Elf64_Rela, "r_info");
            const old_info = try readLeU64(object_bytes, info_offset);
            const symbol_index = old_info >> 32;
            const new_info = (symbol_index << 32) | relocation_type;
            try writeLeU64(object_bytes, info_offset, new_info);
            return;
        }
    }

    return error.MissingRelocationSection;
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

fn extractMoveWideOpcode(opcode: u32) u2 {
    return @intCast((opcode >> 29) & 0x3);
}

fn expectedSignedMoveWideImmediate(value: i64, shift: u6, negate_slice: bool) u16 {
    const raw: u64 = @bitCast(value);
    const slice: u16 = @intCast((raw >> shift) & 0xFFFF);
    return if (negate_slice) ~slice else slice;
}

fn decodeAdrpPageTarget(opcode: u32, site_address: u64) !u64 {
    const immlo = (opcode >> 29) & 0x3;
    const immhi = (opcode >> 5) & 0x7FFFF;
    const raw = immlo | (immhi << 2);
    const page_delta = try decodeSignedScaledImmediate(raw, 21, 12);
    const site_page = site_address & ~@as(u64, 0xFFF);
    const result = @as(i128, @intCast(site_page)) + @as(i128, page_delta);
    if (result < 0 or result > std.math.maxInt(u64)) return error.Overflow;
    return @intCast(result);
}

fn extractUnsignedLoadStoreImmediate(opcode: u32, shift: u6) u64 {
    const imm12 = (opcode >> 10) & 0xFFF;
    return @as(u64, imm12) << shift;
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

fn runCommandCaptureStdout(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        defer allocator.free(result.stdout);
        std.debug.print("command failed: {s}\n{s}\n{s}\n", .{
            argv[0],
            result.stdout,
            result.stderr,
        });
        return error.CommandFailed;
    }

    return result.stdout;
}

fn runCommandExpectExitCode(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    expected_exit_code: u8,
) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code == expected_exit_code) return;
            std.debug.print("command exited with unexpected code: {s} -> {d} (expected {d})\n{s}\n{s}\n", .{
                argv[0],
                code,
                expected_exit_code,
                result.stdout,
                result.stderr,
            });
            return error.UnexpectedExitCode;
        },
        else => {
            std.debug.print("command did not exit normally: {s}\n{s}\n{s}\n", .{
                argv[0],
                result.stdout,
                result.stderr,
            });
            return error.CommandFailed;
        },
    }
}
