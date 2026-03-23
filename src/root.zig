const sdk_mod = @import("sdk/root.zig");

pub const core = @import("core/root.zig");
pub const format = @import("format/root.zig");
pub const isa = @import("isa/root.zig");
pub const frontends = @import("frontends/root.zig");
pub const sdk = sdk_mod;

// Legacy convenience aliases.
pub const aarch64 = isa.aarch64;
pub const elf = format.elf;
pub const payload = core.payload;
pub const rewriter = core.rewriter;
pub const bundle = core.bundle;
pub const apply = core.apply;

pub const XRegistersNamed = sdk_mod.XRegistersNamed;
pub const XRegisters = sdk_mod.XRegisters;
pub const FpRegistersNamed = sdk_mod.FpRegistersNamed;
pub const FpRegisters = sdk_mod.FpRegisters;
pub const HookContext = sdk_mod.HookContext;
pub const InstrumentCallback = sdk_mod.InstrumentCallback;

pub const Rewriter = core.rewriter.Rewriter;
pub const InstrumentHookSpec = core.rewriter.InstrumentHookSpec;
pub const InstrumentObjectSpec = core.rewriter.InstrumentObjectSpec;
pub const ReplaceHookSpec = core.rewriter.ReplaceHookSpec;
pub const ReplaceObjectSpec = core.rewriter.ReplaceObjectSpec;
pub const RewriteReport = core.rewriter.RewriteReport;
pub const InstrumentRewriteReport = core.rewriter.InstrumentRewriteReport;
pub const ReplaceRewriteReport = core.rewriter.ReplaceRewriteReport;
pub const BundleBuildSpec = core.bundle.BuildSpec;
pub const BundleManifest = core.bundle.Manifest;
pub const BundleHookSpec = core.bundle.HookSpec;
pub const BundleTarget = core.bundle.TargetSpec;
pub const HookLocator = core.bundle.HookLocator;
pub const HookTargetKind = core.bundle.HookTargetKind;
