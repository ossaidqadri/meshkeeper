"""A fake AX12 pairs with the daemon: search, topology, M1 per radio, M2 with the router's SSID and key."""

import re
import subprocess

from conftest import sh

AGENT_SOCK = "/tmp/bench-run/agent.sock"
VM_SOCK = "/tmp/bench-run/vm.sock"
# fronthaul_2g wifinet0 ("MK") and fronthaul_5g wifinet1 ("MK 5GHz"), plus ssid_suffix " Ext"; see tests/conftest.py
WANT_2G = ("MK Ext", "bench-test-key-24")
WANT_5G = ("MK 5GHz Ext", "bench-test-key-5g")


def run_agent(fake_agent):
    return subprocess.run(
        [fake_agent, "--sock", AGENT_SOCK, "--peer", VM_SOCK,
         "--want-2g", ":".join(WANT_2G), "--want-5g", ":".join(WANT_5G), "--timeout", "100"],
        capture_output=True, text=True, timeout=130,
    )


def test_fake_satellite_pairs(meshkeeper, fake_agent):
    ssh = meshkeeper
    done = run_agent(fake_agent)
    out = done.stderr
    print("\n" + out)
    assert done.returncode == 0, out
    # M2 verified on the agent side: both authenticators, decrypted SSID and key as configured.
    for ssid, key in (WANT_2G, WANT_5G):
        assert re.search(rf'M2 ok radio=\w+ ssid="{ssid}" key="{key}" mac=', out), out
    assert "link metrics answered" in out
    log = sh(ssh, "logread -e meshkeeper")
    assert re.search(r"new agent .*0200.?00a0.?d950", log), log
    for ssid, _ in (WANT_2G, WANT_5G):
        assert f'pushing SSID "{ssid}"' in log, log
    assert "reports link metrics" in log, log
