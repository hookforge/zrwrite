const std = @import("std");

/// Current on-stack runtime metadata ABI version embedded into `HookContext`.
pub const hook_runtime_info_abi_version_current: u16 = 1;

/// Named general-purpose register view for AArch64 callbacks.
pub const XRegistersNamed = extern struct {
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
    x4: u64,
    x5: u64,
    x6: u64,
    x7: u64,
    x8: u64,
    x9: u64,
    x10: u64,
    x11: u64,
    x12: u64,
    x13: u64,
    x14: u64,
    x15: u64,
    x16: u64,
    x17: u64,
    x18: u64,
    x19: u64,
    x20: u64,
    x21: u64,
    x22: u64,
    x23: u64,
    x24: u64,
    x25: u64,
    x26: u64,
    x27: u64,
    x28: u64,
    x29: u64,
    x30: u64,
};

/// Dual view over the 31 AArch64 general-purpose registers.
pub const XRegisters = extern union {
    x: [31]u64,
    named: XRegistersNamed,
};

/// Named 128-bit SIMD / floating-point register view.
pub const FpRegistersNamed = extern struct {
    v0: u128,
    v1: u128,
    v2: u128,
    v3: u128,
    v4: u128,
    v5: u128,
    v6: u128,
    v7: u128,
    v8: u128,
    v9: u128,
    v10: u128,
    v11: u128,
    v12: u128,
    v13: u128,
    v14: u128,
    v15: u128,
    v16: u128,
    v17: u128,
    v18: u128,
    v19: u128,
    v20: u128,
    v21: u128,
    v22: u128,
    v23: u128,
    v24: u128,
    v25: u128,
    v26: u128,
    v27: u128,
    v28: u128,
    v29: u128,
    v30: u128,
    v31: u128,
};

/// Dual view over the 32 AArch64 SIMD / floating-point registers.
pub const FpRegisters = extern union {
    v: [32]u128,
    named: FpRegistersNamed,
};

/// Runtime image metadata made visible to payload code.
///
/// Address semantics:
/// - `site_linked_address`: static image address used during patching / RE
/// - `site_runtime_address`: live runtime address observed by the CPU
/// - `load_bias`: runtime delta such that `runtime = linked + load_bias`
pub const HookRuntimeInfo = extern struct {
    abi_version: u16,
    flags: u16,
    reserved0: u32,
    load_bias: i64,
    site_linked_address: u64,
    site_runtime_address: u64,
};

/// Payload-side helper that converts between linked and runtime addresses.
pub const TargetImage = struct {
    load_bias: i64,
    site_linked_address: u64,
    site_runtime_address: u64,

    pub fn init(load_bias: i64, site_linked_address: u64, site_runtime_address: u64) TargetImage {
        return .{
            .load_bias = load_bias,
            .site_linked_address = site_linked_address,
            .site_runtime_address = site_runtime_address,
        };
    }

    pub fn fromRuntimeInfo(info: HookRuntimeInfo) TargetImage {
        return .{
            .load_bias = info.load_bias,
            .site_linked_address = info.site_linked_address,
            .site_runtime_address = info.site_runtime_address,
        };
    }

    pub fn loadBias(self: TargetImage) i64 {
        return self.load_bias;
    }

    pub fn siteLinked(self: TargetImage) u64 {
        return self.site_linked_address;
    }

    pub fn siteRuntime(self: TargetImage) u64 {
        return self.site_runtime_address;
    }

    pub fn resolveLinked(self: TargetImage, linked_address: u64) u64 {
        return addSignedAddressOffset(linked_address, self.load_bias);
    }

    pub fn toLinked(self: TargetImage, runtime_address: u64) u64 {
        return subtractSignedAddressOffset(runtime_address, self.load_bias);
    }

    pub fn ptr(self: TargetImage, comptime T: type, linked_address: u64) *T {
        return @ptrFromInt(self.resolveLinked(linked_address));
    }

    pub fn ptrConst(self: TargetImage, comptime T: type, linked_address: u64) *const T {
        return @ptrFromInt(self.resolveLinked(linked_address));
    }

    pub fn fnPtr(self: TargetImage, comptime F: type, linked_address: u64) F {
        return @ptrFromInt(self.resolveLinked(linked_address));
    }
};

/// Stable callback context ABI shared by injected payload code.
pub const HookContext = extern struct {
    regs: XRegisters,
    sp: u64,
    pc: u64,
    cpsr: u32,
    pad: u32,
    fpregs: FpRegisters,
    fpsr: u32,
    fpcr: u32,
    runtime: HookRuntimeInfo,

    /// Returns a helper view over the target image address model.
    pub fn target(self: *const HookContext) TargetImage {
        return TargetImage.fromRuntimeInfo(self.runtime);
    }
};

comptime {
    std.debug.assert(@sizeOf(XRegisters) == @sizeOf([31]u64));
    std.debug.assert(@sizeOf(FpRegisters) == @sizeOf([32]u128));
    std.debug.assert(@alignOf(FpRegisters) == @alignOf([32]u128));
    std.debug.assert(@sizeOf(FpRegistersNamed) == @sizeOf([32]u128));
    std.debug.assert(@sizeOf(HookRuntimeInfo) == 32);
    std.debug.assert(@offsetOf(HookRuntimeInfo, "load_bias") == 8);
    std.debug.assert(@offsetOf(HookRuntimeInfo, "site_linked_address") == 16);
    std.debug.assert(@offsetOf(HookRuntimeInfo, "site_runtime_address") == 24);
    std.debug.assert(@alignOf(HookContext) == @alignOf(FpRegisters));
    std.debug.assert(@offsetOf(HookContext, "runtime") % @alignOf(HookRuntimeInfo) == 0);
}

/// Payload callback type used by V1 instrument detours.
pub const InstrumentCallback = *const fn (address: u64, ctx: *HookContext) callconv(.c) void;

fn addSignedAddressOffset(base: u64, signed_offset: i64) u64 {
    const result = @as(i128, @intCast(base)) + @as(i128, signed_offset);
    if (result < 0 or result > std.math.maxInt(u64)) {
        @panic("zrwrite TargetImage address overflow");
    }
    return @intCast(result);
}

fn subtractSignedAddressOffset(base: u64, signed_offset: i64) u64 {
    const result = @as(i128, @intCast(base)) - @as(i128, signed_offset);
    if (result < 0 or result > std.math.maxInt(u64)) {
        @panic("zrwrite TargetImage address overflow");
    }
    return @intCast(result);
}

test "target image converts linked and runtime addresses" {
    const image = TargetImage.init(0x7fff_1000, 0x10b64, 0x7fff_1b64);

    try std.testing.expectEqual(@as(i64, 0x7fff_1000), image.loadBias());
    try std.testing.expectEqual(@as(u64, 0x10b64), image.siteLinked());
    try std.testing.expectEqual(@as(u64, 0x7fff_1b64), image.siteRuntime());
    try std.testing.expectEqual(@as(u64, 0x7fff_2000), image.resolveLinked(0x1000));
    try std.testing.expectEqual(@as(u64, 0x2000), image.toLinked(0x7fff_3000));
}

test "target image also supports negative runtime bias conversions" {
    const image = TargetImage.init(-0x4000, 0x8000, 0x4000);

    try std.testing.expectEqual(@as(u64, 0x5000), image.resolveLinked(0x9000));
    try std.testing.expectEqual(@as(u64, 0x9000), image.toLinked(0x5000));
}

test "hook context exposes a target image helper view" {
    var ctx = std.mem.zeroes(HookContext);
    ctx.runtime = .{
        .abi_version = hook_runtime_info_abi_version_current,
        .flags = 0,
        .reserved0 = 0,
        .load_bias = 0x1000,
        .site_linked_address = 0x10b64,
        .site_runtime_address = 0x11b64,
    };

    const image = ctx.target();
    try std.testing.expectEqual(@as(u64, 0x12000), image.resolveLinked(0x11000));
    try std.testing.expectEqual(@as(u64, 0x10b64), image.siteLinked());
    try std.testing.expectEqual(@as(u64, 0x11b64), image.siteRuntime());
}
