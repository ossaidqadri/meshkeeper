const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // .safe by default: bounds, overflow and null checks stay on in the
    // binary that parses untrusted frames. A panic restarts under procd
    // instead of silently corrupting memory.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .safe });
    const strip = optimize != .debug;

    // All of meshkeeper's own code, at the requested mode.
    const daemon = b.createModule(.{
        .root_source_file = b.path("src/daemon.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        // One poll loop, no threads: drops std's thread pool and locking.
        .single_threaded = true,
    });
    // The root decides std's mode. ReleaseSafe std is mostly speed inlining
    // (645 KB against 365 KB); size wins on a router, and the checks that
    // matter are the ones in daemon.zig, which keeps them.
    const root = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = if (optimize == .debug) .debug else .small,
        .strip = strip,
        .single_threaded = true,
        .imports = &.{.{ .name = "daemon", .module = daemon }},
    });

    const exe = b.addExecutable(.{ .name = "meshkeeper", .root_module = root });
    b.installArtifact(exe);

    // Every test twice: debug, and at the shipping mode so the fuzz tests run
    // against optimized code with its checks on.
    const test_step = b.step("test", "Run unit and fuzz tests on the host");
    for ([_]std.builtin.Optimize{ .debug, .safe }) |mode| {
        const tests = b.addTest(.{ .root_module = b.createModule(.{
            .root_source_file = b.path("src/daemon.zig"),
            .target = b.graph.host,
            .optimize = mode,
        }) });
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}
