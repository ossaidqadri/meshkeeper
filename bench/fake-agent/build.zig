const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The controller's own wire code, so the agent speaks exactly what meshkeeper parses and builds.
    const cmdu = b.createModule(.{ .root_source_file = b.path("../../src/cmdu.zig"), .target = target, .optimize = optimize });
    const wsc = b.createModule(.{ .root_source_file = b.path("../../src/wsc.zig"), .target = target, .optimize = optimize });

    const exe = b.addExecutable(.{ .name = "fake-agent", .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "cmdu", .module = cmdu },
            .{ .name = "wsc", .module = wsc },
        },
    }) });
    b.installArtifact(exe);
}
