const builtin = @import("builtin");
const std = @import("std");
const zrwrite = @import("zrwrite");
const common = @import("../common.zig");

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

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/shared/compute.c",
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

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/shared/compute.c",
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

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-Wl,-e,_main",
        "tests/fixtures/macho/layout/macho_shifted_data_ref.S",
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

    try common.runCommand(allocator, &.{ "chmod", "+x", output_path });
    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 7);
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

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fobjc-arc",
        "tests/fixtures/macho/layout/macho_objc_methodlist.m",
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

    try common.runCommand(allocator, &.{ "chmod", "+x", output_path });
    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 7);

    const objc_info = try common.runCommandCaptureStdout(allocator, &.{ "xcrun", "dyld_info", "-objc", output_path });
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

    try common.runCommand(allocator, &.{
        "xcrun",
        "--sdk",
        "macosx",
        "clang",
        "-arch",
        "arm64",
        "-O0",
        "-g0",
        "-fobjc-arc",
        "tests/fixtures/macho/layout/macho_objc_methodlist.m",
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

    try common.runCommand(allocator, &.{ "chmod", "+x", output_path });
    try common.runCommand(allocator, &.{ "codesign", "-f", "-s", "-", output_path });
    try common.runCommandExpectExitCode(allocator, &.{output_path}, 7);

    const objc_info = try common.runCommandCaptureStdout(allocator, &.{ "xcrun", "dyld_info", "-objc", output_path });
    defer allocator.free(objc_info);
    try std.testing.expect(std.mem.indexOf(u8, objc_info, "-[ArMethodListDemo answer]") != null);
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

    try common.runCommand(allocator, &.{
        "zig",
        "cc",
        "-target",
        "aarch64-macos",
        "-O0",
        "-g0",
        "tests/fixtures/shared/compute.c",
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
        "clang",
        "-target",
        "arm64-apple-macos11",
        "-c",
        "tests/fixtures/macho/layout/macho_readonly_pointer_payload.S",
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
