"""Boot the QEMU router to a root shell, power it off at the end.

Shape taken from aparcar/openwrt-tests' QEMUNetworkStrategy (Apache-2.0), cut down to
the shell: ssh joins in B2.
"""

import enum
from typing import ClassVar

import attr
from labgrid import step, target_factory
from labgrid.strategy import Strategy, StrategyError


class Status(enum.Enum):
    unknown = 0
    off = 1
    shell = 2


@target_factory.reg_driver
@attr.s(eq=False)
class OpenWrtStrategy(Strategy):
    bindings: ClassVar[dict] = {
        "qemu": "QEMUDriver",
        "shell": "ShellDriver",
    }

    status = attr.ib(default=Status.unknown)

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
        elif state == Status.shell:
            self.target.activate(self.qemu)
            self.qemu.on()
            self.target.activate(self.shell)
        self.status = state
