# Building

Needs Zig 0.17.

```
zig build test
zig build -Dtarget=mips-linux-musleabi -Dcpu=mips32r2 -Drelease
```

The second line gives `zig-out/bin/meshkeeper` for ath79 (MIPS 24Kc); change the target for your router's CPU. Safety checks stay on in release, on purpose.

`src/testdata/wsc_vectors.zig` came from the Python prototype whose M2 the AX12 first accepted, so the Zig side is tested byte for byte against an independent implementation. The prototype is in git history (before its removal commit) if the vectors ever need regenerating.
