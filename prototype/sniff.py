"""Listen for IEEE 1905 frames and print one line per CMDU.

Usage: uv run python sniff.py [seconds] [interface-name-substring]
"""

import sys

from scapy.all import conf, sniff

CMDU_TYPES = {
    0x0000: "topology discovery",
    0x0001: "topology notification",
    0x0002: "topology query",
    0x0003: "topology response",
    0x0004: "vendor specific",
    0x0007: "AP-autoconfig search",
    0x0008: "AP-autoconfig response",
    0x0009: "AP-autoconfig WSC",
    0x000A: "AP-autoconfig renew",
}


def show(pkt) -> None:
    raw = bytes(pkt)
    payload = raw[14:]
    if len(payload) < 8:
        return
    msg_type = int.from_bytes(payload[2:4], "big")
    msg_id = int.from_bytes(payload[4:6], "big")
    name = CMDU_TYPES.get(msg_type, f"type 0x{msg_type:04x}")
    print(f"{pkt.time:.1f} {pkt.src} -> {pkt.dst} {name} mid={msg_id} len={len(payload)}", flush=True)


def main() -> None:
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    want = sys.argv[2] if len(sys.argv) > 2 else "Wi-Fi"
    iface = next(i for i in conf.ifaces.values() if want.lower() in (i.name + i.description).lower())
    print(f"listening on {iface.name} ({iface.description}) for {seconds}s", flush=True)
    sniff(iface=iface, filter="ether proto 0x893a", prn=show, store=False, timeout=seconds)


if __name__ == "__main__":
    main()
