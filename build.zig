const std = @import("std");

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

    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zrwrite", .module = mod },
            },
        }),
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    const test_step = b.step("test", "Run unit and integration tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_zrstd_tests.step);
    test_step.dependOn(&run_integration_tests.step);
}
