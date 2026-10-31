"""Sysupgrade persistence and the owut remove list, on the x86-64 target (malta has no sysupgrade image).

One scenario, in file order, each test building on the one before: install, upgrade inside apk's
database, sysupgrade (which wipes apk's database but keeps the package's files), reinstall, remove.
Run with --lg-env targets/qemu-x86-64.yaml and the x86_64 apks.
"""

import os
import re
import subprocess
import threading
import time

import pytest

from conftest import MESHKEEPER_CONFIG, setup_wireless

PORT = os.environ.get("BENCH_SSH_PORT", "2222")
KEY = "/tmp/bench-run/id_ed25519"
IMAGE = ".cache/openwrt-25.12.6-x86-64-generic-squashfs-combined.img.gz"
SSH_OPTS = ["-i", KEY, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes"]

KEEP_PATHS = [
    "/usr/sbin/meshkeeper", "/etc/init.d/meshkeeper", "/etc/rc.d/S99meshkeeper",
    "/etc/capabilities/meshkeeper.json", "/usr/share/acl.d/meshkeeper.json",
    "/lib/upgrade/keep.d/meshkeeper", "/etc/meshkeeper/probe",
    "/www/luci-static/resources/view/meshkeeper/mesh.js",
    "/usr/share/luci/menu.d/luci-app-meshkeeper.json",
    "/usr/share/rpcd/acl.d/luci-app-meshkeeper.json",
    "/lib/upgrade/keep.d/luci-app-meshkeeper",
]
ENTRIES = ["meshkeeper/if-installed", "luci-app-meshkeeper/if-installed"]


def rsh(cmd, check=True, timeout=300):
    """One command over ssh to the VM; a fresh connection each time, so it survives reboots."""
    for attempt in range(6):  # 255 is ssh itself failing (VM busy, network restarting), not the command
        p = subprocess.run(["ssh", *SSH_OPTS, "-p", PORT, "root@127.0.0.1", cmd], capture_output=True, text=True, timeout=timeout)
        if p.returncode != 255 or not check:
            break
        time.sleep(5)
    if check:
        assert p.returncode == 0, f"{cmd}: exit {p.returncode}\n{p.stdout}\n{p.stderr}"
    return p.stdout.strip()


def put(local, remote):
    subprocess.run(["scp", "-O", *SSH_OPTS, "-P", PORT, local, f"root@127.0.0.1:{remote}"], check=True, timeout=300)


CONSOLE = bytearray()  # the tail of what the serial console printed


def drain_console(strategy, stop):
    """Keep reading the serial console. Nobody else does after provisioning, and when the
    socket backlog fills (a reboot prints a lot) QEMU stalls the guest's serial writes: GRUB
    then sits at its countdown for ever."""
    while not stop.is_set():
        try:
            chunk = strategy.qemu.read(size=65536, timeout=0.5)
        except Exception:
            chunk = b""
            time.sleep(0.5)
        if chunk:
            CONSOLE.extend(chunk)
            del CONSOLE[:-100_000]


def console_tail():
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", CONSOLE.decode(errors="replace"))[-6000:]


def wait_ssh(seconds):
    end = time.monotonic() + seconds
    last = b""
    while time.monotonic() < end:
        p = subprocess.run(["ssh", *SSH_OPTS, "-p", PORT, "root@127.0.0.1", "true"], capture_output=True, timeout=30)
        if p.returncode == 0:
            return
        last = p.stderr
        time.sleep(3)
    raise AssertionError(f"no ssh after reboot ({last!r}); console tail:\n{console_tail()}")


def daemon_pid():
    return rsh("for p in $(pidof meshkeeper); do grep -q '^Uid:[[:space:]]*32768' /proc/$p/status && echo $p; done; true")


def wait_daemon(seconds=60):
    for _ in range(seconds):
        pid = daemon_pid()
        if pid:
            return pid
        time.sleep(1)
    state = rsh("ubus list | tr '\\n' ' '; echo; ps | grep -E 'netifd|wpad|hostapd' | grep -v grep; "
                "ls /sys/class/ieee80211; wifi status 2>&1 | head -25; logread | tail -40", check=False)
    raise AssertionError("daemon not running:\n" + state)


def owut_remove():
    return rsh("uci -q get attendedsysupgrade.owut.remove", check=False)


def apk_new():
    found = rsh("find /etc /usr /lib /www -name '*.apk-new' 2>/dev/null", check=False).split()
    return [f for f in found if f != "/etc/config/meshkeeper.apk-new"]


@pytest.fixture(scope="module")
def vm(router, strategy, request):
    """The x86 router, booted and reachable over ssh; apk paths from the command line."""
    opts = {k: request.config.getoption(k) for k in ("--meshkeeper-apk", "--luci-apk", "--meshkeeper-apk-r2")}
    if not all(opts.values()):
        pytest.skip("--meshkeeper-apk, --luci-apk and --meshkeeper-apk-r2 are required (x86_64 apks)")
    stop = threading.Event()
    reader = threading.Thread(target=drain_console, args=(strategy, stop), daemon=True)
    reader.start()
    yield opts
    stop.set()
    reader.join(timeout=5)


def test_install_sets_owut_remove(vm):
    rsh("apk update")
    rsh("apk add owut")
    assert rsh("uci -q get attendedsysupgrade.owut"), "owut has no config section"
    # The daemon needs netifd's wireless object, so give the VM simulated radios first.
    setup_wireless(rsh)
    put(vm["--meshkeeper-apk"], "/tmp/meshkeeper.apk")
    put(vm["--luci-apk"], "/tmp/luci-app-meshkeeper.apk")
    rsh("apk add --allow-untrusted --force-non-repository /tmp/meshkeeper.apk /tmp/luci-app-meshkeeper.apk")
    for line in MESHKEEPER_CONFIG.strip().split("\n")[1:]:  # point it at the wireless sections above
        rsh(line)
    rsh("/etc/init.d/meshkeeper restart")
    wait_daemon()
    remove = owut_remove()
    for e in ENTRIES:
        assert e in remove.split(), remove
    rsh("mkdir -p /etc/meshkeeper && echo bench > /etc/meshkeeper/probe && chown -R meshkeeper:meshkeeper /etc/meshkeeper")


def test_sysupgrade_lists_every_keep_path(vm):
    listed = rsh("sysupgrade -l").split()
    missing = [p for p in KEEP_PATHS if p not in listed]
    assert missing == [], f"not in `sysupgrade -l`: {missing}\n{listed}"


def test_apk_upgrade_keeps_owut_entries(vm):
    """An apk upgrade must not run pre-deinstall (which would clear the entries) and leaves no .apk-new."""
    before = daemon_pid()
    put(vm["--meshkeeper-apk-r2"], "/tmp/meshkeeper-r2.apk")
    rsh("apk add --allow-untrusted --force-non-repository /tmp/meshkeeper-r2.apk")
    assert "meshkeeper-0.2.0-r2" in rsh("apk list -I meshkeeper")
    assert wait_daemon() != before, "daemon was not restarted by the upgrade"
    remove = owut_remove()
    for e in ENTRIES:
        assert e in remove.split(), remove
    assert apk_new() == []


def test_sysupgrade_keeps_everything(vm):
    put(IMAGE, "/tmp/image.img.gz")
    # The connection dies with the reboot; the exit status says nothing.
    print("\nsysupgrade:", rsh("sysupgrade -v /tmp/image.img.gz 2>&1", check=False, timeout=600))
    time.sleep(10)
    wait_ssh(300)
    # Nobody starts it: procd must have it as a service from the restored init script and rc.d link.
    for _ in range(60):
        if "meshkeeper" in rsh("logread -e meshkeeper", check=False):
            break
        time.sleep(1)
    assert "meshkeeper" in rsh("logread -e meshkeeper", check=False), "the service was not started at boot"
    assert rsh("ubus call service list '{\"name\":\"meshkeeper\"}'", check=False).count('"command"') >= 1
    # The fresh image has none of the packages added for the simulated radios, so netifd has no
    # wireless object and the daemon keeps exiting (and procd respawning it) until it does.
    rsh("apk add wifi-scripts iw")
    rsh("(/etc/init.d/network restart >/dev/null 2>&1 &)")
    time.sleep(10)
    wait_daemon(90)  # picked up by procd's respawn, meshkeeper itself never restarted
    assert rsh("id -u meshkeeper") == "32768"
    for p in KEEP_PATHS:
        rsh(f"test -e {p}")
    assert rsh("apk list -I meshkeeper", check=False) == "", "apk's database should be gone after sysupgrade"


def test_reinstall_after_sysupgrade_over_restored_files(vm):
    # Plain option, not a list: what a user may have written by hand.
    rsh("uci set attendedsysupgrade.owut.remove='foo' && uci commit attendedsysupgrade")
    assert owut_remove() == "foo"
    put(vm["--meshkeeper-apk-r2"], "/tmp/meshkeeper-r2.apk")
    rsh("apk add --allow-untrusted --force-non-repository /tmp/meshkeeper-r2.apk")
    assert "meshkeeper-0.2.0-r2" in rsh("apk list -I meshkeeper")
    assert apk_new() == [], "files restored by sysupgrade made apk write .apk-new"
    wait_daemon()
    remove = owut_remove().split()
    assert "foo" in remove and "meshkeeper/if-installed" in remove, remove


def test_apk_del_clears_owut_entries(vm):
    # Only meshkeeper: the sysupgrade wiped apk's database and the LuCI apk was not reinstalled
    # (apk refuses to delete a package it doesn't know). Its prerm clears both owut entries.
    out = rsh("apk del meshkeeper 2>&1; echo exit=$?", check=False)
    print("\napk del:", out)
    remove = owut_remove().split()
    if any("meshkeeper" in e for e in remove):
        # Run the installed pre-deinstall's owut lines by hand, traced, to see where it goes wrong.
        trace = rsh("uci show attendedsysupgrade; sh -x -c '[ -n \"${IPKG_INSTROOT}\" ] || ! uci -q get attendedsysupgrade.owut >/dev/null || { "
                    "for p in meshkeeper luci-app-meshkeeper; do uci -q del_list attendedsysupgrade.owut.remove=\"$p/if-installed\"; done; "
                    "uci commit attendedsysupgrade; }' 2>&1; uci show attendedsysupgrade; apk list -I | grep -i meshkeeper", check=False)
        raise AssertionError(f"owut list not cleared: {remove}\napk del said: {out}\nby hand:\n{trace}")
    assert not any("meshkeeper" in e for e in remove), remove
    assert "foo" in remove, remove  # not touched
    for _ in range(20):  # default_prerm stops the service; give procd a moment
        if rsh("pidof meshkeeper", check=False) == "":
            break
        time.sleep(1)
    left = rsh("pidof meshkeeper", check=False)
    assert left == "", (f"still running after apk del: {left}\n" + rsh(
        "ls -l /etc/init.d/meshkeeper /etc/rc.d/S99meshkeeper /usr/sbin/meshkeeper 2>&1; "
        "ubus call service list '{\"name\":\"meshkeeper\"}' 2>&1 | head -20; logread -e procd | tail -5", check=False))
