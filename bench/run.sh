#!/bin/sh
# Build the container and run the emulated-router tests. Extra arguments go to pytest.
set -eu
cd "$(dirname "$0")"
# Git for Windows' sh says /d/work/...; podman on Windows needs D:/work/... (pwd -W).
repo=$(cd .. && { pwd -W 2>/dev/null || pwd; })
podman build -q -t meshkeeper-bench -f Containerfile .
# APK_DIR (default .cache/apks) shows up as /apks, e.g. --meshkeeper-apk /apks/meshkeeper-0.2.0-r1.apk
mkdir -p "${APK_DIR:=$repo/bench/.cache/apks}"
podman run --rm -v "$repo:/repo" -v "$APK_DIR:/apks:ro" -e BENCH_SSH_PORT meshkeeper-bench sh -c '
	set -eu
	sh ./fetch.sh
	uv sync --frozen
	exec uv run pytest --lg-env targets/qemu-malta-be.yaml tests "$@"
' sh "$@"

