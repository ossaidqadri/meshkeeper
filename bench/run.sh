#!/bin/sh
# Build the container and run the emulated-router tests. Extra arguments go to pytest.
set -eu
cd "$(dirname "$0")"
# Git for Windows' sh says /d/work/...; podman on Windows needs D:/work/... (pwd -W). It also
# rewrites anything that looks like a path (/apks/x.apk) when calling podman.exe; that's off here.
repo=$(cd .. && { pwd -W 2>/dev/null || pwd; })
export MSYS_NO_PATHCONV=1
podman build -q -t meshkeeper-bench --build-arg DEBIAN_MIRROR="${BENCH_DEBIAN_MIRROR-http://mirrors.edge.kernel.org/debian}" -f Containerfile .
# APK_DIR shows up as /apks, e.g. --meshkeeper-apk /apks/meshkeeper-0.2.0-r1.apk. The default is
# where `build-apks.sh ath79/generic` puts the C6's apks.
mkdir -p "${APK_DIR:=$repo/bench/.run/apks/ath79-generic/out}"
podman run --rm -v "$repo:/repo" -v "$APK_DIR:/apks:ro" -v meshkeeper-zig-cache:/opt/zig-cache -e BENCH_SSH_PORT meshkeeper-bench sh -c '
	set -eu
	sh ./fetch.sh
	uv sync --frozen
	exec uv run pytest --lg-env targets/qemu-malta-be.yaml tests "$@"
' sh "$@"

