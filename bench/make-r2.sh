#!/bin/sh
# Rebuild meshkeeper as release 2 inside an OpenWrt SDK that already built release 1, for the
# bench's upgrade tests. Usage: make-r2.sh <sdk dir>; the apk lands in <sdk>/bin/packages/.
#
# r2's binary must differ from r1's, or procd (which restarts the service on the binary's
# checksum) rightly does nothing on upgrade. So besides PKG_RELEASE, one usage string changes.
# Both edits are made on the SDK's copy of the package; the repo is never touched.
set -eu
sdk=${1:?usage: make-r2.sh <sdk dir>}
pkg=$sdk/package/meshkeeper
sed -i 's/^PKG_RELEASE:=1$/PKG_RELEASE:=2/' "$pkg/Makefile"
sed -i 's/(default: meshkeeper)/(default: meshkeeper, r2)/' "$pkg/src/daemon.zig"
grep -q 'PKG_RELEASE:=2' "$pkg/Makefile" && grep -q 'meshkeeper, r2' "$pkg/src/daemon.zig"
cd "$sdk"
make package/meshkeeper/clean V=s
make package/meshkeeper/compile V=s
