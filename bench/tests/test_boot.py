def run(shell, cmd):
    out, err, code = shell.run(cmd)
    assert code == 0, f"{cmd}: exit {code}, stderr {err}"
    return "\n".join(out).strip()


def test_arch(router):
    shell, _ = router
    assert run(shell, "uname -m") == "mips"


def test_release(router):
    shell, _ = router
    assert "25.12.6" in run(shell, "cat /etc/openwrt_release")


def test_apk_arch(router):
    # `apk --print-arch` prints the arch apk was compiled for ("mips"); the package arch is in /etc/apk/arch.
    shell, _ = router
    assert run(shell, "cat /etc/apk/arch") == "mips_24kc"
    assert "DISTRIB_ARCH='mips_24kc'" in run(shell, "cat /etc/openwrt_release")
