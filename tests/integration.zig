// Keep the integration suites grouped by domain so fixture-heavy coverage stays
// navigable without sacrificing regression coverage.
test {
    _ = @import("integration/elf_workflow.zig");
    _ = @import("integration/elf_replay.zig");
    _ = @import("integration/payload_linker.zig");
    _ = @import("integration/macho_layout.zig");
    _ = @import("integration/macho_runtime.zig");
}
