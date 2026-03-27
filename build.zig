const std = @import("std");

const IntegrationSuite = struct {
    step_name: []const u8,
    description: []const u8,
    path: []const u8,
};

fn addIntegrationSuite(
    b: *std.Build,
    mod: *std.Build.Module,
    optimize: std.builtin.OptimizeMode,
    suite: IntegrationSuite,
) *std.Build.Step.Run {
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(suite.path),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zrwrite", .module = mod },
            },
        }),
    });
    return b.addRunArtifact(tests);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zrwrite", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    const zrstd_mod = b.addModule("zrstd", .{
        .root_source_file = b.path("src/zrstd/root.zig"),
        .target = target,
    });

    const exe = b.addExecutable(.{
        .name = "zrwrite",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zrwrite", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the zrwrite CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const zrstd_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zrstd/root.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zrstd", .module = zrstd_mod },
            },
        }),
    });
    const run_zrstd_tests = b.addRunArtifact(zrstd_tests);

    const integration_suites = [_]IntegrationSuite{
        .{
            .step_name = "test-integration-elf-workflow",
            .description = "Run ELF workflow integration tests",
            .path = "tests/integration/elf_workflow.zig",
        },
        .{
            .step_name = "test-integration-elf-replay",
            .description = "Run AArch64 replay integration tests",
            .path = "tests/integration/elf_replay.zig",
        },
        .{
            .step_name = "test-integration-payload-linker",
            .description = "Run payload linker integration tests",
            .path = "tests/integration/payload_linker.zig",
        },
        .{
            .step_name = "test-integration-macho-layout",
            .description = "Run Mach-O layout integration tests",
            .path = "tests/integration/macho_layout.zig",
        },
        .{
            .step_name = "test-integration-macho-runtime",
            .description = "Run Mach-O runtime integration tests",
            .path = "tests/integration/macho_runtime.zig",
        },
    };

    const integration_step = b.step("test-integration", "Run integration test suites");
    inline for (integration_suites) |suite| {
        const run_suite = addIntegrationSuite(b, mod, optimize, suite);
        integration_step.dependOn(&run_suite.step);

        const suite_step = b.step(suite.step_name, suite.description);
        suite_step.dependOn(&run_suite.step);
    }

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_zrstd_tests.step);
    test_step.dependOn(integration_step);
}
