"""The installed package: service, jail, files, log, upgrade, footprint."""

import re

import pytest

from conftest import sh

# Measured 452 kB resident, 124 kB of it private (RssAnon), once std was built for size and big
# buffers stopped staying resident; ~10% headroom each. The private part is what the daemon
# really costs: code pages are shared and the kernel can drop them.
RSS_LIMIT_KB = 500
ANON_LIMIT_KB = 140


def pid(ssh):
    """The daemon itself: pidof also lists the ujail parent, which runs as root."""
    return sh(ssh, "for p in $(pidof meshkeeper); do grep -q '^Uid:[[:space:]]*32768' /proc/$p/status && echo $p; done; true")


def status_field(ssh, p, field):
    return sh(ssh, f"sed -n 's/^{field}:[[:space:]]*//p' /proc/{p}/status")


def test_config_readable_by_service_user(meshkeeper):
    # Runs after `meshkeeper` edited the config with uci, which keeps the mode the package installed.
    assert sh(meshkeeper, "find /etc/config/meshkeeper -perm -004") == "/etc/config/meshkeeper"


def test_service_runs_jailed_as_service_user(meshkeeper):
    ssh = meshkeeper
    p = pid(ssh)
    assert status_field(ssh, p, "Uid").split()[0] == "32768"
    sh(ssh, f"test ! -e /proc/{p}/root/bin/ubus")
    # Read-only jail root: a write must fail.
    out, _, code = ssh.run(f"touch /proc/{p}/root/probe")
    assert code != 0, "the jail root accepted a write"


def test_no_apk_new_files(meshkeeper):
    found = sh(meshkeeper, "find /etc /usr /lib /www -name '*.apk-new' 2>/dev/null", check=False).split()
    assert [f for f in found if f != "/etc/config/meshkeeper.apk-new"] == []


def test_log_shows_probe_subscription_and_no_errors(meshkeeper):
    ssh = meshkeeper
    log = sh(ssh, "logread -e meshkeeper")
    objects = int(sh(ssh, "ubus list 'hostapd.*' | wc -l"))
    m = re.search(r"watching probe requests on (\d+) hostapd interface\(s\)", log)
    assert m, log
    assert int(m.group(1)) == objects, (m.group(1), objects, log)
    bad = [l for l in log.splitlines() if re.search(r"err|fail|denied|timeout", l, re.I)]
    assert bad == [], "\n".join(bad)


def test_rss_and_binary_size(meshkeeper):
    ssh = meshkeeper
    p = pid(ssh)
    rss = int(status_field(ssh, p, "VmRSS").split()[0])
    anon = int(status_field(ssh, p, "RssAnon").split()[0])
    size = int(sh(ssh, "wc -c < /usr/sbin/meshkeeper"))
    print(f"\nVmRSS {rss} kB (RssAnon {anon} kB), binary {size} bytes")
    assert rss < RSS_LIMIT_KB
    assert anon < ANON_LIMIT_KB


def test_upgrade_restarts_service(meshkeeper, request):
    ssh = meshkeeper
    r2 = request.config.getoption("--meshkeeper-apk-r2")
    if not r2:
        pytest.skip("--meshkeeper-apk-r2 is required")
    before = pid(ssh)
    ssh.put(r2, "/tmp/meshkeeper-r2.apk")
    sh(ssh, "apk add --allow-untrusted --force-non-repository /tmp/meshkeeper-r2.apk")
    sh(ssh, "sleep 5")
    after = pid(ssh)
    assert after != before, f"pid unchanged: {before}"
    assert re.search(r"meshkeeper-[\d.]+-r2 ", sh(ssh, "apk list -I meshkeeper"))
    assert "procd_set_param file" in sh(ssh, "cat /etc/init.d/meshkeeper")
    test_no_apk_new_files(ssh)
