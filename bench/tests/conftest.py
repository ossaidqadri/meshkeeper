import os
import time

import pytest

RUN_DIR = "/tmp/bench-run"  # unix sockets don't work on the host mount; matches targets/*.yaml


@pytest.fixture(scope="session")
def router(strategy):
    """Boots the emulated router once per session; returns (shell driver, boot seconds)."""
    os.makedirs(RUN_DIR, exist_ok=True)
    started = time.monotonic()
    strategy.transition("shell")
    seconds = time.monotonic() - started
    print(f"\nboot to shell: {seconds:.1f} s")
    yield strategy.shell, seconds
    strategy.transition("off")
