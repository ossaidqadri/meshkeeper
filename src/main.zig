//! Entry point only. The daemon lives in daemon.zig, its own module built
//! ReleaseSafe; this root (and with it std) is built ReleaseSmall. See build.zig.

const daemon = @import("daemon");

pub const std_options = daemon.std_options;
pub const panic = daemon.panic;
pub const main = daemon.main;
