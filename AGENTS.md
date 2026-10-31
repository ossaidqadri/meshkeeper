# AGENTS.md

Installing meshkeeper on a router rather than working on the code? Follow [docs/install-with-ai.md](docs/install-with-ai.md).

- Tests: `zig build test` (runs every test twice, debug and the shipping mode). Emulated router: `sh bench/quick.sh` (needs podman).
- `src/daemon.zig` and everything it imports stays a safe build; `build.zig` refuses to compile it otherwise. Only std is built for size.
- `src/controller.zig` stays pure (no I/O); wiring lives in `src/daemon.zig`.
- Parsers of untrusted or file input get a fuzz test.
- Only made-up addresses in code, tests and docs: MACs `02:00:00:...`, SSIDs like "MK". Never a real device's.
- Commit messages say why: the concrete failure, not just the change.
