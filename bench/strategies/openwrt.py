"""Boot the QEMU router to a root shell, then to ssh; power it off at the end.

Shape taken from aparcar/openwrt-tests' QEMUNetworkStrategy (Apache-2.0).

States: off, shell (serial console), ssh (VM networking set up, key installed, ssh forwarded).
The ssh port on the host is $BENCH_SSH_PORT, default 2222.
"""

import enum
import os
import subprocess
from pathlib import Path
from typing import ClassVar

import attr
from labgrid import step, target_factory
from labgrid.strategy import Strategy, StrategyError

RUN_DIR = Path("/tmp/bench-run")  # unix sockets don't work on the host mount; matches targets/*.yaml
KEY = RUN_DIR / "id_ed25519"
LAN = "192.168.1.1"

# eth0 (user net, slirp gateway .2, DNS .3) is already in br-lan; eth1 is the satellite's dgram link.
NETWORK_SETUP = """\
uci set network.lan.gateway=192.168.1.2
uci set network.lan.dns=192.168.1.3
uci add_list network.@device[0].ports=eth1
uci commit network
/etc/init.d/network restart
"""


class Status(enum.Enum):
    unknown = 0
    off = 1
    shell = 2
    ssh = 3


@target_factory.reg_driver
@attr.s(eq=False)
class OpenWrtStrategy(Strategy):
    bindings: ClassVar[dict] = {
        "qemu": "QEMUDriver",
        "shell": "ShellDriver",
        "ssh": "SSHDriver",
    }

    status = attr.ib(default=Status.unknown)

    def _provision(self):
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        if not KEY.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(KEY)], check=True)
        pub = Path(f"{KEY}.pub")
        for line in NETWORK_SETUP.splitlines():
            self.shell.run_check(line)
        self.shell.run_check("mkdir -p /etc/dropbear && chmod 700 /etc/dropbear")
        self.shell.run_check(f"echo '{pub.read_text().strip()}' > /etc/dropbear/authorized_keys")
        self.shell.run_check("chmod 600 /etc/dropbear/authorized_keys")

    def _forward(self):
        port = int(os.environ.get("BENCH_SSH_PORT", "2222"))
        self.qemu.add_port_forward("tcp", "127.0.0.1", port, LAN, 22, "lan")
        ns = self.ssh.networkservice
        ns.address, ns.port = "127.0.0.1", port

    @step(args=["state"])
    def transition(self, state, *, step):
        if not isinstance(state, Status):
            state = Status[state]
        if state == Status.unknown:
            raise StrategyError(f"can not transition to {state}")
        if self.status == state:
            step.skip("nothing to do")
            return
        if state == Status.off:
            self.target.activate(self.qemu)
            self.qemu.off()
        elif state in (Status.shell, Status.ssh):
            if self.status in (Status.unknown, Status.off):
                RUN_DIR.mkdir(parents=True, exist_ok=True)
                self.target.activate(self.qemu)
                self.qemu.on()
                self.target.activate(self.shell)
            if state == Status.ssh:
                self._provision()
                self._forward()
                self.target.activate(self.ssh)
        self.status = state
