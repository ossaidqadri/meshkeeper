import pytest


def pytest_addoption(parser):
    parser.addoption("--meshkeeper-apk", help="meshkeeper apk to install (built for the target's package arch)")
    parser.addoption("--luci-apk", help="luci-app-meshkeeper apk to install")
    parser.addoption("--meshkeeper-apk-r2", help="same package with a bumped release, for the upgrade tests")


def pytest_collection_modifyitems(config, items):
    """test_sysupgrade.py runs on the x86-64 target only (malta can't sysupgrade); the rest on malta."""
    x86 = "x86" in (config.getoption("--lg-env") or "")
    for item in items:
        on_x86 = item.path.name == "test_sysupgrade.py"
        if on_x86 != x86:
            item.add_marker(pytest.mark.skip(reason="runs on the x86-64 target" if on_x86 else "runs on the malta target"))
