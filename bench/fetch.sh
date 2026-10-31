#!/bin/sh
# Fetch the OpenWrt malta/be initramfs kernel into .cache/, checked against the release's sha256sums.
set -eu
VERSION=25.12.6
BASE=https://downloads.openwrt.org/releases/$VERSION/targets/malta/be
FILE=openwrt-$VERSION-malta-be-vmlinux-initramfs.elf
cd "$(dirname "$0")"
mkdir -p .cache
if [ -f ".cache/$FILE.sum" ] && [ -f ".cache/$FILE" ] && (cd .cache && sha256sum -c "$FILE.sum" >/dev/null 2>&1); then
	exit 0
fi
curl -fsSL -o .cache/sha256sums "$BASE/sha256sums"
curl -fsSL -o ".cache/$FILE" "$BASE/$FILE"
grep -F "*$FILE" .cache/sha256sums > ".cache/$FILE.sum"
(cd .cache && sha256sum -c "$FILE.sum")
