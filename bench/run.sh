#!/bin/sh
# Build the container and run the emulated-router tests. Extra arguments go to pytest.
set -eu
cd "$(dirname "$0")"
podman build -q -t meshkeeper-bench -f Containerfile .
# APK_DIR (default .cache/apks) shows up as /apks, e.g. --meshkeeper-apk /apks/meshkeeper-0.2.0-r1.apk
mkdir -p "${APK_DIR:=$PWD/.cache/apks}"
podman run --rm -v "$PWD/..:/repo" -v "$APK_DIR:/apks:ro" -e BENCH_SSH_PORT meshkeeper-bench sh -c '
	set -eu
	sh ./fetch.sh
	uv sync --frozen
	exec uv run pytest --lg-env targets/qemu-malta-be.yaml tests "$@"
' sh "$@"

