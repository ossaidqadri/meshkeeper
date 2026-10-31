import os
import subprocess
import time

import pytest


@pytest.fixture(scope="session")
def router(strategy):
    """Boots the emulated router once per session; returns (shell driver, seconds to the shell)."""
    started = time.monotonic()
    strategy.transition("shell")
    seconds = time.monotonic() - started
    print(f"\nboot to shell: {seconds:.1f} s")
    strategy.transition("ssh")  # VM networking, eth1 into br-lan, key, ssh forward
    yield strategy.shell, seconds
    strategy.transition("off")


@pytest.fixture(scope="session")
def ssh(router, strategy):
    return strategy.ssh


# Made-up identifiers only (the repo's test set); the keys are throwaway test values.
WIRELESS = """\
set -e
wifi config
for s in $(uci show wireless | sed -n "s/^wireless\\.\\(default_radio[0-9]*\\)=.*/\\1/p"); do uci delete wireless.$s; done
uci set wireless.radio0.band=2g; uci set wireless.radio0.channel=1; uci set wireless.radio0.disabled=0; uci set wireless.radio0.country=US
uci set wireless.radio1.band=5g; uci set wireless.radio1.channel=36; uci set wireless.radio1.disabled=0; uci set wireless.radio1.country=US
uci set wireless.wifinet0=wifi-iface
uci set wireless.wifinet0.device=radio0; uci set wireless.wifinet0.mode=ap; uci set wireless.wifinet0.network=lan
uci set wireless.wifinet0.ssid=MK; uci set wireless.wifinet0.encryption=psk2; uci set wireless.wifinet0.key=bench-test-key-24
uci set wireless.wifinet0.multi_ap=2
uci set wireless.meshbh=wifi-iface
uci set wireless.meshbh.device=radio1; uci set wireless.meshbh.mode=ap; uci set wireless.meshbh.network=lan
uci set wireless.meshbh.ssid=bh-benchtest; uci set wireless.meshbh.hidden=1; uci set wireless.meshbh.encryption=psk2
uci set wireless.meshbh.key=0123456789abcdef0123456789abcdef; uci set wireless.meshbh.multi_ap=1; uci set wireless.meshbh.wds=1
uci set wireless.wifinet1=wifi-iface
uci set wireless.wifinet1.device=radio1; uci set wireless.wifinet1.mode=ap; uci set wireless.wifinet1.network=lan
uci set wireless.wifinet1.ssid='MK 5GHz'; uci set wireless.wifinet1.encryption=psk2; uci set wireless.wifinet1.key=bench-test-key-5g
uci set wireless.wifinet1.multi_ap=2; uci set wireless.wifinet1.wps_pushbutton=1
uci set wireless.wifinet1.multi_ap_backhaul_ssid=bh-benchtest
uci set wireless.wifinet1.multi_ap_backhaul_key=0123456789abcdef0123456789abcdef
uci commit wireless
wifi reload
"""

MESHKEEPER_CONFIG = """\
set -e
uci set meshkeeper.main.interface=br-lan
uci set meshkeeper.main.fronthaul_2g=wifinet0
uci set meshkeeper.main.fronthaul_5g=wifinet1
uci set meshkeeper.main.ssid_suffix=' Ext'
uci set meshkeeper.main.steering=log
uci commit meshkeeper
"""


def setup_wireless(run):
    """Simulated radios (mac80211_hwsim, 3 of them) and the README-style wireless config, hostapd up.

    `run(cmd, check=True)` runs a command on the router and returns its stdout."""
    run("apk update")
    run("apk del wpad-basic-mbedtls; apk add wpad-mbedtls kmod-mac80211-hwsim")
    run("apk info -e wpad-mbedtls && /etc/init.d/wpad restart")  # the running one is still wpad-basic
    # The x86 image ships no wifi handler scripts, so netifd has no network.wireless object (malta does).
    run("apk add wifi-scripts iw")
    run("ubus list network.wireless >/dev/null 2>&1 || (/etc/init.d/network restart >/dev/null 2>&1 &)")
    run("sleep 10; ubus list network.wireless")
    run("rmmod mac80211_hwsim 2>/dev/null; modprobe mac80211_hwsim radios=3")
    run("sleep 3; iw dev >/dev/null; ls /sys/class/ieee80211")
    for line in WIRELESS.strip().split("\n"):  # one call per line keeps a failure attributable
        run(line)
    for _ in range(30):
        if run("ubus list 'hostapd.*' | wc -l", check=False) not in ("", "0"):
            break
        run("sleep 1")


@pytest.fixture(scope="session")
def meshkeeper(router, ssh, request):
    """The router with simulated radios, a README-style wireless config and meshkeeper installed."""
    apk = request.config.getoption("--meshkeeper-apk")
    luci = request.config.getoption("--luci-apk")
    if not apk or not luci:
        pytest.skip("--meshkeeper-apk and --luci-apk are required")
    setup_wireless(lambda cmd, check=True: sh(ssh, cmd, check))
    ssh.put(apk, "/tmp/meshkeeper.apk")
    ssh.put(luci, "/tmp/luci-app-meshkeeper.apk")
    # --force-non-repository: the initramfs root is RAM, apk warns the package is lost on reboot.
    sh(ssh, "apk add --allow-untrusted --force-non-repository /tmp/meshkeeper.apk /tmp/luci-app-meshkeeper.apk")
    # Quick loop: the package as released, running a binary just built on the laptop.
    binary = request.config.getoption("--meshkeeper-bin")
    if binary:
        # The installed one is already running ("Text file busy"); a rename replaces it anyway.
        ssh.put(binary, "/tmp/meshkeeper.bin")
        sh(ssh, "chmod 755 /tmp/meshkeeper.bin && mv /tmp/meshkeeper.bin /usr/sbin/meshkeeper")
    for line in MESHKEEPER_CONFIG.strip().split("\n")[1:]:
        sh(ssh, line)
    sh(ssh, "/etc/init.d/meshkeeper restart; sleep 8")
    return ssh


@pytest.fixture(scope="session")
def fake_agent():
    """Builds bench/fake-agent from the repo's own cmdu.zig and wsc.zig; returns the binary path."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "..", "fake-agent")
    subprocess.run(
        ["zig", "build", "-Dtarget=x86_64-linux-musl", "-Doptimize=ReleaseSafe",
         "--prefix", "/tmp/fake-agent", "--cache-dir", "/tmp/fake-agent-cache"],
        cwd=src, check=True,
    )
    return "/tmp/fake-agent/bin/fake-agent"


def sh(driver, cmd, check=True):
    """Run a command, return its stdout as one string."""
    out, err, code = driver.run(cmd)
    if check:
        assert code == 0, f"{cmd}: exit {code}\n{chr(10).join(err)}\n{chr(10).join(out)}"
    return "\n".join(out).strip()
