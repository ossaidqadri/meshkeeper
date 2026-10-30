const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // .safe by default: bounds, overflow and null checks stay on in the
    // binary that parses untrusted frames. A panic restarts under procd
    // instead of silently corrupting memory.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .debug,
    });

    const exe = b.addExecutable(.{ .name = "meshkeeper", .root_module = mod });
    b.installArtifact(exe);

    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = b.graph.host,
        .optimize = .debug,
    }) });
    const run_tests = b.addRunArtifact(tests);
    b.step("test", "Run unit and fuzz tests on the host").dependOn(&run_tests.step);
}
