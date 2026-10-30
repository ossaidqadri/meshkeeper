"""Prototype Multi-AP controller driven over SSH through relay scripts on an OpenWrt router.

The router runs relay/recv1905.uc (prints 1905 frames) and relay/send1905.uc
(sends one frame). All protocol logic runs here.

Stages, each opt-in:
  (default)    observe: decode and print, send nothing
  --respond    answer AP-Autoconfiguration Search as controller
  --configure  also answer M1 with M2 carrying the router's own SSIDs/keys
"""

import argparse
import os
import subprocess
import sys
import time

import cmdu as c
import wsc


def ssh_cmd(args) -> list[str]:
    return ["ssh", "-i", os.path.expanduser(args.key), "-o", "BatchMode=yes", f"root@{args.router}"]


def router(args, command: str) -> str:
    return subprocess.run(ssh_cmd(args) + [command], capture_output=True, text=True, check=True).stdout.strip()


def load_bss(args) -> dict[int, wsc.BssConfig]:
    """Fronthaul settings per WSC RF band, read from the router's own UCI config."""
    out = {}
    for band, section in ((wsc.RF_BAND_24, args.iface24), (wsc.RF_BAND_5, args.iface5)):
        ssid = router(args, f"uci -q get wireless.{section}.ssid")
        key = router(args, f"uci -q get wireless.{section}.key")
        if not ssid or not 8 <= len(key) <= 63:
            sys.exit(f"wireless.{section}: need an ssid and an 8-63 character passphrase")
        out[band] = wsc.BssConfig(ssid=ssid, passphrase=key)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--router", default="192.168.1.1")
    p.add_argument("--key", default="~/.ssh/archer-c6_ed25519")
    p.add_argument("--iface", default="br-lan")
    p.add_argument("--iface24", default="wifinet0", help="UCI wifi-iface whose SSID/key the agent's 2.4 GHz radio gets")
    p.add_argument("--iface5", default="wifinet1", help="UCI wifi-iface whose SSID/key the agent's 5 GHz radio gets")
    p.add_argument("--agent", help="only talk to this agent AL MAC")
    p.add_argument("--respond", action="store_true")
    p.add_argument("--configure", action="store_true")
    p.add_argument("--bands", choices=["24", "5", "both"], default="24",
                   help="which agent radios --configure may touch; start with 24 so a 5 GHz backhaul stays up")
    p.add_argument("--seconds", type=int, default=120)
    args = p.parse_args()
    if args.configure:
        args.respond = True

    al_mac = bytes.fromhex(router(args, f"cat /sys/class/net/{args.iface}/address").replace(":", ""))
    agent = bytes.fromhex(args.agent.replace(":", "")) if args.agent else None
    bss = load_bss(args) if args.configure else {}
    uuid = al_mac + al_mac[:4] + b"\x00" * 6
    mid = int.from_bytes(os.urandom(2), "big")
    last_m2: dict[bytes, float] = {}
    bands = {"24": {wsc.RF_BAND_24}, "5": {wsc.RF_BAND_5}, "both": {wsc.RF_BAND_24, wsc.RF_BAND_5}}[args.bands]
    mode = "configure" if args.configure else "respond" if args.respond else "observe"
    print(f"controller AL MAC {c.mac_str(al_mac)}, mode {mode}", flush=True)
    for band, b in bss.items():
        print(f"  band {band}: will hand out SSID {b.ssid!r} (key not shown)", flush=True)

    def send(frame: bytes, what: str) -> None:
        print(f"  -> {what} ({len(frame)} bytes)", flush=True)
        subprocess.run(ssh_cmd(args) + [f"ucode -S /tmp/send1905.uc {frame.hex()} {args.iface}"], check=True)

    recv = subprocess.Popen(ssh_cmd(args) + [f"ucode -S /tmp/recv1905.uc {args.iface}"], stdout=subprocess.PIPE, text=True)
    deadline = time.monotonic() + args.seconds
    try:
        for line in recv.stdout:
            if time.monotonic() > deadline:
                break
            f = c.parse_frame(bytes.fromhex(line.strip()))
            if f is None or f.src == al_mac:
                continue
            sender = f.tlv(c.TLV_AL_MAC) or f.src
            if agent and sender != agent and f.src != agent:
                continue
            if f.msg_type in (c.MSG_VENDOR_SPECIFIC, c.MSG_TOPOLOGY_DISCOVERY) or not f.tlvs:
                continue
            print(f"{time.strftime('%H:%M:%S')} {c.mac_str(f.src)} {f.name} mid={f.mid} tlvs={[hex(t) for t, _ in f.tlvs]}", flush=True)

            if f.msg_type == c.MSG_AP_AUTOCONFIG_SEARCH and args.respond:
                if f.tlv(c.TLV_SEARCHED_SERVICE) not in (None, bytes([1, c.SERVICE_CONTROLLER])):
                    continue
                band = (f.tlv(c.TLV_AUTOCONFIG_FREQ_BAND) or bytes([c.BAND_24]))[0]
                tlvs = [
                    (c.TLV_SUPPORTED_ROLE, bytes([c.ROLE_REGISTRAR])),
                    (c.TLV_SUPPORTED_FREQ_BAND, bytes([band])),
                    (c.TLV_SUPPORTED_SERVICE, bytes([1, c.SERVICE_CONTROLLER])),
                    # Profile 1, like prplMesh: some certified agents fail to parse
                    # richer responses, and profile 1 needs no 802.1Q TLVs in M2.
                    (c.TLV_MULTI_AP_PROFILE, bytes([1])),
                ]
                send(c.build_frame(sender, al_mac, c.MSG_AP_AUTOCONFIG_RESPONSE, f.mid, tlvs), f"autoconfig response, band {band}")

            elif f.msg_type == c.MSG_TOPOLOGY_QUERY and args.respond:
                # The agent checks who the controller is before sending M1.
                # Device Information: our AL MAC with one wired interface, no neighbours.
                device_info = al_mac + bytes([1]) + al_mac + c.MEDIA_IEEE_802_3AB.to_bytes(2, "big") + bytes([0])
                tlvs = [
                    (c.TLV_DEVICE_INFO, device_info),
                    (c.TLV_SUPPORTED_SERVICE, bytes([1, c.SERVICE_CONTROLLER])),
                    (c.TLV_MULTI_AP_PROFILE, bytes([1])),
                ]
                send(c.build_frame(f.src, al_mac, c.MSG_TOPOLOGY_RESPONSE, f.mid, tlvs), "topology response")

            elif f.msg_type == c.MSG_AP_AUTOCONFIG_WSC:
                caps, m1raw = f.tlv(c.TLV_AP_RADIO_BASIC_CAPS), f.tlv(c.TLV_WSC)
                if not caps or not m1raw:
                    continue
                m1 = wsc.parse_m1(m1raw)
                ruid = caps[:6]
                print(f"  M1 mid={f.mid} from radio {c.mac_str(ruid)}, mac {c.mac_str(m1.mac)}, rf_bands 0x{m1.rf_bands:02x}, "
                      f"auth 0x{m1.auth_flags:04x}, encr 0x{m1.encr_flags:04x}", flush=True)
                if not args.configure or m1.rf_bands not in bands:
                    continue
                # Every M1 carries a fresh nonce and key, so each one gets its own M2;
                # only throttle bursts so a retry storm can't flood the agent.
                now = time.monotonic()
                if now - last_m2.get(ruid, -10.0) < 3:
                    continue
                cfg = bss.get(m1.rf_bands)
                if cfg is None:
                    print(f"  no SSID for rf_bands 0x{m1.rf_bands:02x}, not answering", flush=True)
                    continue
                m2 = wsc.build_m2(m1, cfg, uuid)
                mid = (mid + 1) & 0xFFFF
                tlvs = [(c.TLV_AP_RADIO_IDENTIFIER, ruid), (c.TLV_WSC, m2)]
                send(c.build_frame(f.src, al_mac, c.MSG_AP_AUTOCONFIG_WSC, mid, tlvs), f"M2 mid={mid} for {cfg.ssid!r}")
                last_m2[ruid] = now
    finally:
        recv.terminate()


if __name__ == "__main__":
    main()
