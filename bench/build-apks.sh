#!/bin/sh
# Build meshkeeper-<ver>-r1 and a bumped -r2 apk (plus the LuCI apk) from git HEAD for one OpenWrt
# target, e.g. `sh bench/build-apks.sh ath79/generic`. The apks land in bench/.run/apks/<target>/.
#
# The SDK image (Containerfile.sdk) holds the host tools, SDK and Zig, so after the first build
# nothing is downloaded. Zig's cache lives in a named volume and survives between builds.
# r2 exists for the upgrade tests; make-r2.sh explains how it differs from r1.
set -eu
target=${1:?usage: build-apks.sh <openwrt target, e.g. ath79/generic>}
tag=meshkeeper-sdk:$(echo "$target" | tr / -)
cd "$(dirname "$0")/.."
# Git for Windows' sh says /d/work/...; podman on Windows needs D:/work/... (pwd -W).
repo=$({ pwd -W 2>/dev/null || pwd; })
export MSYS_NO_PATHCONV=1  # keep /src, /out as container paths
run=bench/.run/apks/$(echo "$target" | tr / -)
rm -rf "$run" && mkdir -p "$run/src" "$run/out"
git archive HEAD | tar -x -C "$run/src"
mkdir -p bench/.cache  # Containerfile.sdk looks here for an already downloaded SDK

podman build -q -t "$tag" --build-arg TARGET="$target" \
	--build-arg DEBIAN_MIRROR="${BENCH_DEBIAN_MIRROR-http://mirrors.edge.kernel.org/debian}" \
	-f bench/Containerfile.sdk bench >/dev/null
podman run --rm -v "$repo/$run/src:/src:ro" -v "$repo/$run/out:/out" \
	-v meshkeeper-zig-cache:/root/.cache/zig "$tag" sh -c '
	set -e
	pkg=package/meshkeeper
	mkdir -p $pkg
	cp -r /src/Makefile /src/files /src/src /src/build.zig /src/build.zig.zon /src/LICENSE $pkg/
	# One package directory, so one target builds both packages.
	make $pkg/compile V=s > /out/build.log 2>&1 || { tail -60 /out/build.log; exit 1; }
	cp $(find bin/packages -name "*.apk") /out/
	sh /src/bench/make-r2.sh /sdk > /out/build-r2.log 2>&1 || { tail -60 /out/build-r2.log; exit 1; }
	cp $(find bin/packages -name "*r2.apk") /out/
'
ls -l "$run/out"/*.apk
