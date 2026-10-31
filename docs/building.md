# Building

Needs Zig 0.17.

```
zig build test
zig build -Dtarget=mips-linux-musleabi -Dcpu=mips32r2 -Drelease
```

The second line gives `zig-out/bin/meshkeeper` for ath79 (MIPS 24Kc); change the target for your router's CPU. Safety checks stay on in release, on purpose.

`prototype/` is the Python version that first proved the AX12 accepts a non-TP-Link controller. Its M2 builder is what the satellite accepted, so the Zig side is tested byte for byte against the vectors it generates (`cd prototype && uv run python gen_vectors.py`).
