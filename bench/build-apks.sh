#!/bin/sh
# Build meshkeeper-<ver>-r1 and a bumped -r2 apk for one OpenWrt target inside the SDK. Runs in a
# debian:bookworm container; usage, from the repo root:
#
#   git archive HEAD -o snap.tar && mkdir src out && tar -xf snap.tar -C src
#   podman run --rm -v $PWD/src:/src:ro -v $PWD/out:/out -v $PWD/bench/build-apks.sh:/b.sh:ro \
#       debian:bookworm sh /b.sh ath79/generic
#
# r2 exists for the upgrade test; make-r2.sh explains how it differs from r1 (a sed on the
# container's copy of the sources; /src and the repo are never touched). CI runs the same script.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
	build-essential gawk gettext libncurses-dev libssl-dev zlib1g-dev xz-utils wget \
	file curl zstd rsync unzip bzip2 python3 python3-setuptools swig perl ca-certificates git >/dev/null

TARGET="$1"
base="https://downloads.openwrt.org/releases/25.12.6/targets/$TARGET"
curl -fsSL -o /tmp/sums "$base/sha256sums"
grep 'openwrt-sdk-.*\.tar\.zst$' /tmp/sums > /tmp/sdk.sum
file=$(awk '{print $2}' /tmp/sdk.sum); file=${file#\*}
echo "SDK: $file"
curl -fsSL -o "/tmp/$file" "$base/$file"
( cd /tmp && sha256sum -c sdk.sum )

mkdir -p /build/sdk
tar --zstd -xf "/tmp/$file" -C /build/sdk --strip-components=1

pkg=/build/sdk/package/meshkeeper
mkdir -p $pkg
cp -r /src/Makefile /src/files /src/src /src/build.zig /src/build.zig.zon /src/LICENSE $pkg/
cd /build/sdk
make defconfig 2>&1 | tail -20
# One package directory, so one target builds both packages.
make package/meshkeeper/compile V=s > /out/build.log 2>&1 || { tail -60 /out/build.log; exit 1; }
find bin/packages -name '*.apk'
cp $(find bin/packages -name '*.apk') /out/

sh /src/bench/make-r2.sh /build/sdk > /out/build-r2.log 2>&1 || { tail -60 /out/build-r2.log; exit 1; }
find bin/packages -name '*r2.apk'
cp $(find bin/packages -name '*r2.apk') /out/
