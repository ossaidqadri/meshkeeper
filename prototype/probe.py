"""Ask an agent for its topology once and print what it reports, including
the SSIDs it is broadcasting (AP Operational BSS TLV). Sends one Topology Query.

Usage: uv run python probe.py <agent-al-mac>
"""

import os
import subprocess
import sys
import time

import cmdu as c

KEY = os.path.expanduser("~/.ssh/archer-c6_ed25519")
SSH = ["ssh", "-i", KEY, "-o", "BatchMode=yes", "root@192.168.1.1"]


def main() -> None:
    agent = bytes.fromhex(sys.argv[1].replace(":", ""))
    al_mac = bytes.fromhex(subprocess.run(SSH + ["cat /sys/class/net/br-lan/address"], capture_output=True, text=True, check=True).stdout.strip().replace(":", ""))
    mid = int.from_bytes(os.urandom(2), "big")
    recv = subprocess.Popen(SSH + ["ucode -S /tmp/recv1905.uc br-lan"], stdout=subprocess.PIPE, text=True)
    time.sleep(2)
    frame = c.build_frame(agent, al_mac, c.MSG_TOPOLOGY_QUERY, mid, [(c.TLV_MULTI_AP_PROFILE, bytes([1]))])
    subprocess.run(SSH + [f"ucode -S /tmp/send1905.uc {frame.hex()} br-lan"], check=True)
    deadline = time.monotonic() + 10
    try:
        for line in recv.stdout:
            f = c.parse_frame(bytes.fromhex(line.strip()))
            if f and f.msg_type == c.MSG_TOPOLOGY_RESPONSE and f.mid == mid:
                print(f"topology response tlvs={[hex(t) for t, _ in f.tlvs]}")
                for v in f.all(c.TLV_AP_OPERATIONAL_BSS):
                    for ruid, bsses in c.parse_operational_bss(v):
                        print(f"  radio {c.mac_str(ruid)}: " + ", ".join(f"{s!r} ({c.mac_str(b)})" for b, s in bsses))
                return
            if time.monotonic() > deadline:
                print("no topology response within 10 s")
                return
    finally:
        recv.terminate()


if __name__ == "__main__":
    main()
