def pytest_addoption(parser):
    parser.addoption("--meshkeeper-apk", help="meshkeeper apk (mips_24kc) to install")
    parser.addoption("--luci-apk", help="luci-app-meshkeeper apk to install")
    parser.addoption("--meshkeeper-apk-r2", help="same package with a bumped release, for the upgrade test")
