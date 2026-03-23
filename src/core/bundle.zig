const std = @import("std");

pub const bundle_magic = "ZRPB";
pub const bundle_version: u16 = 1;

pub const Architecture = enum {
    aarch64,
    x86_64,
};

pub const OperatingSystem = enum {
    linux,
    macos,
};

pub const BinaryFormat = enum {
    elf,
    macho,
};

pub const ObjectFormat = enum {
    elf,
    macho,
};

pub const HookKind = enum {
    instrument,
    replace,
};

pub const HookTargetKind = enum {
    symbol,
    virtual_address,
    file_offset,
};

pub const HookLocator = struct {
    kind: HookTargetKind = .symbol,
    symbol: []const u8 = "",
    virtual_address: u64 = 0,
    file_offset: u64 = 0,

    pub fn fromSymbol(name: []const u8) HookLocator {
        return .{
            .kind = .symbol,
            .symbol = name,
        };
    }

    pub fn fromVirtualAddress(address: u64) HookLocator {
        return .{
            .kind = .virtual_address,
            .virtual_address = address,
        };
    }

    pub fn fromFileOffset(offset: u64) HookLocator {
        return .{
            .kind = .file_offset,
            .file_offset = offset,
        };
    }
};

pub const TargetSpec = struct {
    arch: Architecture,
    os: OperatingSystem,
    binary_format: BinaryFormat,
};

pub const PayloadSpec = struct {
    object_format: ObjectFormat = .elf,
};

pub const MetaPayloadSpec = struct {
    object_path: []const u8,
    object_format: ObjectFormat = .elf,
};

pub const MetaHookLocator = struct {
    kind: HookTargetKind = .symbol,
    symbol: []const u8 = "",
    virtual_address: []const u8 = "",
    file_offset: []const u8 = "",
};

pub const HookSpec = struct {
    kind: HookKind = .instrument,
    target: HookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
    /// Number of contiguous 32-bit instructions to steal starting at the hook
    /// site. `1` keeps the classic single-instruction detour behavior.
    ///
    /// Current Linux/ELF AArch64 limitation:
    /// - values greater than `1` are supported only for straight-line windows
    ///   whose displaced instructions are all raw-trampoline-safe
    stolen_instruction_count: u8 = 1,
};

pub const Manifest = struct {
    bundle_version: u32 = 1,
    target: TargetSpec,
    payload: PayloadSpec = .{},
    hooks: []const HookSpec,
};

pub const BuildSpec = struct {
    target: TargetSpec,
    payload_object_path: []const u8,
    payload_object_format: ObjectFormat = .elf,
    hooks: []const HookSpec,
};

pub const MetaBuildSpec = struct {
    target: TargetSpec,
    payload: MetaPayloadSpec,
    hooks: []const MetaHookSpec,
};

pub const MetaHookSpec = struct {
    kind: HookKind = .instrument,
    target: MetaHookLocator,
    handler_symbol: []const u8,
    log_message: []const u8 = "",
    stolen_instruction_count: u8 = 1,
};

const Header = extern struct {
    magic: [4]u8,
    version: u16,
    reserved: u16,
    manifest_offset: u64,
    manifest_size: u64,
    payload_offset: u64,
    payload_size: u64,
};

pub const OwnedBundle = struct {
    parsed: std.json.Parsed(Manifest),
    payload_object: []const u8,

    pub fn deinit(self: *OwnedBundle) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn manifest(self: *const OwnedBundle) *const Manifest {
        return &self.parsed.value;
    }
};

/// Keeps the parsed meta JSON alive while exposing the resolved `BuildSpec`.
///
/// The returned `build_spec` borrows storage from the parsed JSON arena, so the
/// caller must keep this object alive until bundle creation is finished.
pub const OwnedBuildSpec = struct {
    parsed: std.json.Parsed(MetaBuildSpec),
    build_spec: BuildSpec,

    pub fn deinit(self: *OwnedBuildSpec) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn writeToPath(allocator: std.mem.Allocator, output_path: []const u8, spec: BuildSpec) !void {
    const bundle_bytes = try createBytes(allocator, spec);
    defer allocator.free(bundle_bytes);

    const file = try std.fs.cwd().createFile(output_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bundle_bytes);
}

pub fn createBytes(allocator: std.mem.Allocator, spec: BuildSpec) ![]u8 {
    const payload_bytes = try std.fs.cwd().readFileAlloc(allocator, spec.payload_object_path, std.math.maxInt(usize));
    defer allocator.free(payload_bytes);
    return createBytesFromPayload(allocator, spec, payload_bytes);
}

/// Load a human-authored JSON bundle description.
///
/// `payload.object_path` is resolved relative to the meta file location so a
/// multi-hook project can keep its payload object and meta file together
/// without relying on the caller's current working directory.
pub fn loadBuildSpecFromMetaPath(allocator: std.mem.Allocator, meta_path: []const u8) !OwnedBuildSpec {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, meta_path, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return loadBuildSpecFromMetaBytes(allocator, meta_path, bytes);
}

pub fn loadBuildSpecFromMetaBytes(
    allocator: std.mem.Allocator,
    meta_path: []const u8,
    meta_bytes: []const u8,
) !OwnedBuildSpec {
    var parsed = try std.json.parseFromSlice(MetaBuildSpec, allocator, meta_bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();

    const resolved_payload_path = try resolveMetaRelativePath(
        parsed.arena.allocator(),
        meta_path,
        parsed.value.payload.object_path,
    );
    const resolved_hooks = try parsed.arena.allocator().alloc(HookSpec, parsed.value.hooks.len);
    for (parsed.value.hooks, resolved_hooks) |meta_hook, *resolved_hook| {
        resolved_hook.* = .{
            .kind = meta_hook.kind,
            .target = try resolveMetaHookLocator(meta_hook.target),
            .handler_symbol = meta_hook.handler_symbol,
            .log_message = meta_hook.log_message,
            .stolen_instruction_count = meta_hook.stolen_instruction_count,
        };
    }

    return .{
        .parsed = parsed,
        .build_spec = .{
            .target = parsed.value.target,
            .payload_object_path = resolved_payload_path,
            .payload_object_format = parsed.value.payload.object_format,
            .hooks = resolved_hooks,
        },
    };
}

pub fn createBytesFromPayload(allocator: std.mem.Allocator, spec: BuildSpec, payload_bytes: []const u8) ![]u8 {
    const manifest = Manifest{
        .target = spec.target,
        .payload = .{ .object_format = spec.payload_object_format },
        .hooks = spec.hooks,
    };
    const manifest_bytes = try encodeManifest(allocator, manifest);
    defer allocator.free(manifest_bytes);

    const header_size = @sizeOf(Header);
    const manifest_offset = header_size;
    const payload_offset = manifest_offset + manifest_bytes.len;
    const total_len = payload_offset + payload_bytes.len;

    const bytes = try allocator.alloc(u8, total_len);
    errdefer allocator.free(bytes);

    writeHeader(bytes[0..header_size], .{
        .magic = .{ 'Z', 'R', 'P', 'B' },
        .version = bundle_version,
        .reserved = 0,
        .manifest_offset = manifest_offset,
        .manifest_size = manifest_bytes.len,
        .payload_offset = payload_offset,
        .payload_size = payload_bytes.len,
    });
    @memcpy(bytes[manifest_offset .. manifest_offset + manifest_bytes.len], manifest_bytes);
    @memcpy(bytes[payload_offset .. payload_offset + payload_bytes.len], payload_bytes);

    return bytes;
}

pub fn loadFromPath(allocator: std.mem.Allocator, bundle_path: []const u8) !OwnedBundle {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, bundle_path, std.math.maxInt(usize));
    defer allocator.free(bytes);
    return loadFromBytes(allocator, bytes);
}

pub fn loadFromBytes(allocator: std.mem.Allocator, bundle_bytes: []const u8) !OwnedBundle {
    if (bundle_bytes.len < @sizeOf(Header)) return error.InvalidBundle;

    const header = readHeader(bundle_bytes[0..@sizeOf(Header)]);
    if (!std.mem.eql(u8, header.magic[0..], bundle_magic)) return error.InvalidBundleMagic;
    if (header.version != bundle_version) return error.UnsupportedBundleVersion;

    const manifest_end = header.manifest_offset + header.manifest_size;
    const payload_end = header.payload_offset + header.payload_size;
    if (manifest_end > bundle_bytes.len or payload_end > bundle_bytes.len) return error.InvalidBundleBounds;

    const manifest_bytes = bundle_bytes[header.manifest_offset..manifest_end];
    const payload_bytes = bundle_bytes[header.payload_offset..payload_end];

    var parsed = try std.json.parseFromSlice(Manifest, allocator, manifest_bytes, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();

    const payload_copy = try parsed.arena.allocator().dupe(u8, payload_bytes);

    return .{
        .parsed = parsed,
        .payload_object = payload_copy,
    };
}

fn encodeManifest(allocator: std.mem.Allocator, manifest: Manifest) ![]u8 {
    var out: std.io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(manifest, .{}, &out.writer);
    return allocator.dupe(u8, out.written());
}

fn resolveMetaRelativePath(
    allocator: std.mem.Allocator,
    meta_path: []const u8,
    value: []const u8,
) ![]const u8 {
    if (std.fs.path.isAbsolute(value)) return value;
    const base_dir = std.fs.path.dirname(meta_path) orelse ".";
    return std.fs.path.join(allocator, &.{ base_dir, value });
}

fn resolveMetaHookLocator(locator: MetaHookLocator) !HookLocator {
    return switch (locator.kind) {
        .symbol => blk: {
            if (locator.symbol.len == 0) return error.MissingTargetSymbol;
            break :blk HookLocator.fromSymbol(locator.symbol);
        },
        .virtual_address => HookLocator.fromVirtualAddress(
            try parseMetaInteger(locator.virtual_address, error.MissingTargetLocator),
        ),
        .file_offset => HookLocator.fromFileOffset(
            try parseMetaInteger(locator.file_offset, error.MissingTargetLocator),
        ),
    };
}

fn parseMetaInteger(value: []const u8, comptime missing_error: anyerror) !u64 {
    if (value.len == 0) return missing_error;
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseUnsigned(u64, value[2..], 16);
    }
    return std.fmt.parseUnsigned(u64, value, 10);
}

fn writeHeader(dest: []u8, header: Header) void {
    std.debug.assert(dest.len >= @sizeOf(Header));
    @memcpy(dest[0..4], &header.magic);
    writeU16(dest[4..6], header.version);
    writeU16(dest[6..8], header.reserved);
    writeU64(dest[8..16], header.manifest_offset);
    writeU64(dest[16..24], header.manifest_size);
    writeU64(dest[24..32], header.payload_offset);
    writeU64(dest[32..40], header.payload_size);
}

fn readHeader(src: []const u8) Header {
    return .{
        .magic = .{ src[0], src[1], src[2], src[3] },
        .version = readU16(src[4..6]),
        .reserved = readU16(src[6..8]),
        .manifest_offset = readU64(src[8..16]),
        .manifest_size = readU64(src[16..24]),
        .payload_offset = readU64(src[24..32]),
        .payload_size = readU64(src[32..40]),
    };
}

fn writeU16(dest: []u8, value: usize) void {
    var le: u16 = @intCast(value);
    le = std.mem.nativeToLittle(u16, le);
    @memcpy(dest, std.mem.asBytes(&le));
}

fn writeU64(dest: []u8, value: usize) void {
    var le: u64 = @intCast(value);
    le = std.mem.nativeToLittle(u64, le);
    @memcpy(dest, std.mem.asBytes(&le));
}

fn readU16(src: []const u8) u16 {
    const ptr: *const [2]u8 = @ptrCast(src.ptr);
    return std.mem.readInt(u16, ptr, .little);
}

fn readU64(src: []const u8) u64 {
    const ptr: *const [8]u8 = @ptrCast(src.ptr);
    return std.mem.readInt(u64, ptr, .little);
}
