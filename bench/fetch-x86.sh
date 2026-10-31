#!/bin/sh
# Fetch the OpenWrt x86-64 squashfs-combined image (BIOS boot) into .cache/, checked against the
# release's sha256sums. The .img.gz is also the file sysupgrade takes; the .img boots in QEMU.
# malta has no sysupgrade image, so the sysupgrade test runs on x86-64.
set -eu
VERSION=25.12.6
BASE=https://downloads.openwrt.org/releases/$VERSION/targets/x86/64
FILE=openwrt-$VERSION-x86-64-generic-squashfs-combined.img.gz
cd "$(dirname "$0")"
mkdir -p .cache
if [ ! -f ".cache/$FILE.sum" ] || ! (cd .cache && sha256sum -c "$FILE.sum" >/dev/null 2>&1); then
	curl -fsSL -o .cache/sha256sums-x86 "$BASE/sha256sums"
	curl -fsSL -o ".cache/$FILE" "$BASE/$FILE"
	grep -F "*$FILE" .cache/sha256sums-x86 > ".cache/$FILE.sum"
	(cd .cache && sha256sum -c "$FILE.sum")
fi
# gunzip warns (exit 2) about trailing padding in OpenWrt's combined images; the data is intact.
[ -f ".cache/${FILE%.gz}" ] || gunzip -kf ".cache/$FILE" || [ $? -eq 2 ]
