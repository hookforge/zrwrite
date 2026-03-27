const std = @import("std");
const zrwrite = @import("zrwrite");
const common = @import("../common.zig");

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

    try common.runCommand(allocator, &.{
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "condbr_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x4000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    try std.testing.expectEqual(@as(usize, 0), loaded.entry_offset);

    const branch_opcode = try common.readLeU32(loaded.image, 4);
    const branch_target = try common.decodePcRelativeTarget(branch_opcode, image_base_address + 4, 19);
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "tstbr_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x5000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    try std.testing.expectEqual(@as(usize, 0), loaded.entry_offset);

    const branch_opcode = try common.readLeU32(loaded.image, 0);
    const branch_target = try common.decodePcRelativeTarget(branch_opcode, image_base_address, 14);
    try std.testing.expectEqual(image_base_address + 8, branch_target);
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "movw_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6000_0000;
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const g3 = common.extractMovWideImmediate(try common.readLeU32(loaded.image, 0));
    const g2 = common.extractMovWideImmediate(try common.readLeU32(loaded.image, 4));
    const g1 = common.extractMovWideImmediate(try common.readLeU32(loaded.image, 8));
    const g0 = common.extractMovWideImmediate(try common.readLeU32(loaded.image, 12));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "movw_prel_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6100_0000;
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const helper_address = image_base_address + helper_layout.entry_offset;
    const on_hit_address = image_base_address + loaded.entry_offset;

    const opcode0 = try common.readLeU32(loaded.image, loaded.entry_offset + 0);
    const opcode1 = try common.readLeU32(loaded.image, loaded.entry_offset + 4);
    const opcode2 = try common.readLeU32(loaded.image, loaded.entry_offset + 8);
    const opcode3 = try common.readLeU32(loaded.image, loaded.entry_offset + 12);

    const delta0: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 0)));
    const delta1: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 4)));
    const delta2: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 8)));
    const delta3: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(on_hit_address + 12)));

    try std.testing.expectEqual(@as(u2, if (delta0 < 0) 0 else 2), common.extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode2));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode3));

    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(delta0, 0, delta0 < 0), common.extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(delta1, 16, false), common.extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(delta2, 32, false), common.extractMovWideImmediate(opcode2));
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(delta3, 48, false), common.extractMovWideImmediate(opcode3));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "movw_sabs_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x1000;
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const helper_address = image_base_address + helper_layout.entry_offset;

    const opcode0 = try common.readLeU32(loaded.image, 0);
    const opcode1 = try common.readLeU32(loaded.image, 4);
    const opcode2 = try common.readLeU32(loaded.image, 8);

    try std.testing.expectEqual(@as(u2, 2), common.extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 2), common.extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 2), common.extractMoveWideOpcode(opcode2));

    const signed_helper: i64 = @intCast(helper_address);
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(signed_helper, 0, false), common.extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(signed_helper, 16, false), common.extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(common.expectedSignedMoveWideImmediate(signed_helper, 32, false), common.extractMovWideImmediate(opcode2));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "got_ld_prel19_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6300_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const slot_address = image_base_address + layout.image_size - @sizeOf(u64);
    const ldr_opcode = try common.readLeU32(loaded.image, 0);
    const literal_target = try common.decodePcRelativeTarget(ldr_opcode, image_base_address, 19);

    try std.testing.expectEqual(slot_address, literal_target);
    try std.testing.expectEqual(image_base_address + helper_layout.entry_offset, try common.readLeU64(loaded.image, layout.image_size - @sizeOf(u64)));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "gotpage_lo15_payload.S", source);
    defer allocator.free(object_bytes);

    const image_base_address: u64 = 0x6400_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const slot_address = image_base_address + layout.image_size - @sizeOf(u64);
    const adrp_opcode = try common.readLeU32(loaded.image, 0);
    const ldr_opcode = try common.readLeU32(loaded.image, 4);

    const slot_page = try common.decodeAdrpPageTarget(adrp_opcode, image_base_address);
    const slot_offset = common.extractUnsignedLoadStoreImmediate(ldr_opcode, 3);

    try std.testing.expectEqual(slot_address & ~@as(u64, 0xFFF), slot_page);
    try std.testing.expectEqual(slot_address, slot_page + slot_offset);
    try std.testing.expectEqual(image_base_address + helper_layout.entry_offset, try common.readLeU64(loaded.image, layout.image_size - @sizeOf(u64)));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "gotrel_payload.S", source);
    defer allocator.free(object_bytes);

    try common.overwriteRelaTypeAtIndex(object_bytes, 0, @intFromEnum(std.elf.R_AARCH64.GOTREL64));
    try common.overwriteRelaTypeAtIndex(object_bytes, 1, @intFromEnum(std.elf.R_AARCH64.GOTREL32));

    const image_base_address: u64 = 0x6500_0000;
    const layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "on_hit");
    const helper_layout = try zrwrite.payload.analyzeObjectBytes(allocator, object_bytes, "helper");
    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", image_base_address, null);
    defer allocator.free(loaded.image);

    const got_base_address = image_base_address + layout.image_size;
    const helper_address = image_base_address + helper_layout.entry_offset;
    const expected_delta: i64 = @intCast(@as(i128, @intCast(helper_address)) - @as(i128, @intCast(got_base_address)));

    try std.testing.expectEqual(expected_delta, try common.readLeI64(loaded.image, loaded.entry_offset + 0));
    try std.testing.expectEqual(@as(i32, @intCast(expected_delta)), try common.readLeI32(loaded.image, loaded.entry_offset + 8));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "movw_gotoff_payload.S", source);
    defer allocator.free(object_bytes);

    try common.overwriteRelaTypeAtIndex(object_bytes, 1, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G0));
    try common.overwriteRelaTypeAtIndex(object_bytes, 2, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G1_NC));
    try common.overwriteRelaTypeAtIndex(object_bytes, 3, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G2_NC));
    try common.overwriteRelaTypeAtIndex(object_bytes, 4, @intFromEnum(std.elf.R_AARCH64.MOVW_GOTOFF_G3));

    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x6600_0000, null);
    defer allocator.free(loaded.image);

    const opcode0 = try common.readLeU32(loaded.image, loaded.entry_offset + 4);
    const opcode1 = try common.readLeU32(loaded.image, loaded.entry_offset + 8);
    const opcode2 = try common.readLeU32(loaded.image, loaded.entry_offset + 12);
    const opcode3 = try common.readLeU32(loaded.image, loaded.entry_offset + 16);

    try std.testing.expectEqual(@as(u2, 2), common.extractMoveWideOpcode(opcode0));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode1));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode2));
    try std.testing.expectEqual(@as(u2, 3), common.extractMoveWideOpcode(opcode3));

    try std.testing.expectEqual(@as(u16, 8), common.extractMovWideImmediate(opcode0));
    try std.testing.expectEqual(@as(u16, 0), common.extractMovWideImmediate(opcode1));
    try std.testing.expectEqual(@as(u16, 0), common.extractMovWideImmediate(opcode2));
    try std.testing.expectEqual(@as(u16, 0), common.extractMovWideImmediate(opcode3));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "gotoff_lo15_payload.S", source);
    defer allocator.free(object_bytes);

    try common.overwriteRelaTypeAtIndex(object_bytes, 3, @intFromEnum(std.elf.R_AARCH64.LD64_GOTOFF_LO15));

    const loaded = try zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x6700_0000, null);
    defer allocator.free(loaded.image);

    const ldr_opcode = try common.readLeU32(loaded.image, loaded.entry_offset + 12);
    try std.testing.expectEqual(@as(u64, 8), common.extractUnsignedLoadStoreImmediate(ldr_opcode, 3));
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

    const object_bytes = try common.compileAarch64AssemblyObject(allocator, "unsupported_relocation_payload.S", source);
    defer allocator.free(object_bytes);

    try common.overwriteFirstRelaType(object_bytes, @intFromEnum(std.elf.R_AARCH64.TLSIE_LD_GOTTPREL_PREL19));

    zrwrite.clearLastLinkDiagnostic();
    try std.testing.expectError(
        error.UnsupportedPayloadRelocation,
        zrwrite.payload.linkObjectBytes(allocator, object_bytes, "on_hit", 0x7000_0000, null),
    );

    const diagnostic = zrwrite.lastLinkDiagnosticMessage() orelse return error.MissingDiagnostic;
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "TLSIE_LD_GOTTPREL_PREL19") != null);
    try std.testing.expect(std.mem.indexOf(u8, diagnostic, "helper") != null);
}
