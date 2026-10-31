#!/bin/sh
# Build the container and run the emulated-router tests. Extra arguments go to pytest.
set -eu
cd "$(dirname "$0")"
podman build -q -t meshkeeper-bench -f Containerfile .
podman run --rm -v "$PWD:/bench" meshkeeper-bench sh -c '
	set -eu
	sh ./fetch.sh
	uv sync --frozen
	exec uv run pytest --lg-env targets/qemu-malta-be.yaml "$@"
' sh "$@"
