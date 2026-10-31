"""The VM has internet and the satellite link (eth1, unix datagram sockets) reaches br-lan."""

import socket

from conftest import sh

AGENT_SOCK = "/tmp/bench-run/agent.sock"
VM_SOCK = "/tmp/bench-run/vm.sock"
SRC = bytes.fromhex("02000000c0de")  # the repo's made-up client MAC


def test_internet(ssh):
    sh(ssh, "apk update")


def test_eth1_in_bridge(ssh):
    state = sh(ssh, "ls /sys/class/net; uci show network | grep -E 'device|ports|gateway'; ls -l /sys/class/net/eth1/ | head -5", check=False)
    assert sh(ssh, "basename $(readlink /sys/class/net/eth1/master)", check=False) == "br-lan", state


def test_frame_from_agent_socket_reaches_br_lan(ssh):
    sh(ssh, "apk add tcpdump")
    # Capture one 1905 frame on br-lan in the background, then send frames from the host side.
    sh(ssh, "rm -f /tmp/cap.txt; (tcpdump -i br-lan -nn -e -c 1 ether proto 0x893a >/tmp/cap.txt 2>&1 &) ; sleep 2")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.bind(AGENT_SOCK)
    except OSError:
        pass
    frame = bytes.fromhex("ffffffffffff") + SRC + bytes.fromhex("893a") + b"\x00" * 46
    for _ in range(5):
        s.sendto(frame, VM_SOCK)
    out = ""
    for _ in range(10):
        out = sh(ssh, "cat /tmp/cap.txt", check=False)
        if "ethertype Unknown (0x893a)" in out or "893a" in out:
            break
        sh(ssh, "sleep 1")
        s.sendto(frame, VM_SOCK)
    s.close()
    assert "02:00:00:00:c0:de" in out, out
