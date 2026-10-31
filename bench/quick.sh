#!/bin/sh
# The fast loop: build the daemon for the C6 with the laptop's Zig, then run the malta tests with
# the released package (downloaded once) running that binary. No OpenWrt SDK, nothing else to
# download. Packaging itself is checked by build-apks.sh and CI. Extra arguments go to pytest.
set -eu
cd "$(dirname "$0")/.."
version=0.2.0
rel=https://github.com/ossaidqadri/meshkeeper/releases/download/v$version
dir=bench/.cache/release-$version
mkdir -p "$dir" bench/.run/quick
for f in meshkeeper-$version-r1-mips_24kc.apk luci-app-meshkeeper-$version-r1.apk; do
	[ -s "$dir/$f" ] || curl -fsSL -o "$dir/$f" "$rel/$f"
done
zig build -Drelease -Dtarget=mips-linux-musleabi -Dcpu=mips32r2 --prefix bench/.run/quick
APK_DIR=$(cd "$dir" && { pwd -W 2>/dev/null || pwd; }) exec sh bench/run.sh \
	--meshkeeper-apk "/apks/meshkeeper-$version-r1-mips_24kc.apk" \
	--luci-apk "/apks/luci-app-meshkeeper-$version-r1.apk" \
	--meshkeeper-bin /repo/bench/.run/quick/bin/meshkeeper "$@"
