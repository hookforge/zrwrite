const impl = @import("core/payload/object.zig");

pub const PayloadLayout = impl.PayloadLayout;
pub const LoadedPayload = impl.LoadedPayload;
pub const analyzeObject = impl.analyzeObject;
pub const analyzeObjectBytes = impl.analyzeObjectBytes;
pub const linkObject = impl.linkObject;
pub const linkObjectBytes = impl.linkObjectBytes;
pub const loadTextOnlyObject = impl.loadTextOnlyObject;
pub const loadTextOnlyObjectBytes = impl.loadTextOnlyObjectBytes;
pub const clearLastLinkDiagnostic = impl.clearLastLinkDiagnostic;
pub const lastLinkDiagnosticMessage = impl.lastLinkDiagnosticMessage;
