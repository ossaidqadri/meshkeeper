# install meshkeeper (for AI agents)

> Instructions for an AI agent installing meshkeeper on someone's OpenWrt router. The person may have given you only the repo link. Find out what you can yourself; ask them only for what you can't.

OBJECTIVE: meshkeeper (and optionally its LuCI page) running on the person's main router, with the router's Wi-Fi set up per the [README's Setup](../README.md#setup), without ever locking them out.

DONE WHEN: `logread -e meshkeeper` on the router shows "watching probe requests on N hostapd interface(s)", the LuCI page Status, Mesh loads, and nothing you added is left in `/tmp`.

## Rules

- Before every command that changes anything, show it and wait for the person's yes. Read-only commands need no confirmation.
- Never reboot, restart the network, run `firstboot` or `sysupgrade`, or change the root password or dropbear/SSH settings. Any of these can lock the person out.
- Never ask for the router password in chat.
- If a check fails or anything looks unexpected, stop and explain.
- Chat-only assistant (no shell)? Give the person one command at a time to paste, and read back their output.

## Steps

1. **Their computer.** Work out the OS (Windows, macOS, Linux) and use matching commands from here on. Windows has `ssh`, `scp` and `curl.exe` built in.
2. **Find the router.** It's the default gateway: Windows `Get-NetRoute 0.0.0.0/0` (or `ipconfig`), macOS `route -n get default`, Linux `ip route`. Confirm it's OpenWrt with `ssh root@<gw> cat /etc/openwrt_release`, or by http://<gw>/ showing LuCI. Not OpenWrt: stop. meshkeeper needs OpenWrt 25.12 or later; installing OpenWrt is out of scope, point them to the [Table of Hardware](https://openwrt.org/toh/start).
3. **SSH access.** Try key login (`ssh -o BatchMode=yes root@<gw> true`). If it needs a password, you can't type it: ask the person to add their public key in LuCI (System, Administration, SSH-Keys), creating one first with `ssh-keygen -t ed25519` if they have none, then retry.
4. **Read-only checks**, in one ssh call:
   `cat /etc/openwrt_release; apk info -e wpad-basic-mbedtls wpad-mbedtls; df -k /overlay; free`
   - Release `25.12` or later, else stop.
   - Arch is `DISTRIB_ARCH` in that file (`apk --print-arch` prints only the CPU family, e.g. `mips`). It must be one of `mips_24kc`, `mipsel_24kc`, `arm_cortex-a7_neon-vfpv4`, `aarch64_cortex-a53`, `x86_64`; anything else is unsupported, stop.
   - At least 1 MB free in `/overlay`.
   - Satellite: meshkeeper only helps with an EasyMesh satellite, e.g. a TP-Link AX12 on stock firmware (see the README's Tested on). Ask the person what they have; no satellite, stop.
5. **Show findings and the plan** (steps 6 to 9 with the exact commands), and wait for a go-ahead.
6. **Back up** the wireless config to their computer: `scp -O root@<gw>:/etc/config/wireless ./wireless.backup`. `-O` because dropbear has no sftp. Tell them where it is.
7. **Full wpad**, if `wpad-basic-mbedtls` is installed. The swap drops Wi-Fi for a few seconds; on Wi-Fi the session dies mid-command, so recommend a cable, and run it detached either way:
   `ssh root@<gw> 'apk update >/dev/null && (apk del wpad-basic-mbedtls && apk add wpad-mbedtls && /etc/init.d/wpad restart) >/tmp/wpad-swap.log 2>&1 </dev/null &'`
   Reconnect after ~30 s, read `/tmp/wpad-swap.log`, check `apk info -e wpad-mbedtls`.
8. **Install.** Get the latest release from https://api.github.com/repos/ossaidqadri/meshkeeper/releases/latest, download the assets `meshkeeper-<version>-r<n>-<arch>.apk` and `luci-app-meshkeeper-<version>-r<n>.apk` with `curl -fLO`, then:
   `scp -O meshkeeper-*.apk luci-app-meshkeeper-*.apk root@<gw>:/tmp/`
   `ssh root@<gw> 'apk add --allow-untrusted /tmp/meshkeeper-*.apk /tmp/luci-app-meshkeeper-*.apk'`
9. **Configure** per the [README's Setup](../README.md#setup) (backhaul network, WPS, `/etc/config/meshkeeper`), one confirmed `uci` change at a time, then `wifi reload`. That also drops Wi-Fi for a few seconds, so run it detached like step 7 (`ssh root@<gw> '(wifi reload) >/dev/null 2>&1 </dev/null &'`) and reconnect. Then walk the person through pairing the satellite (Setup, step 3).
10. **Verify** the DONE WHEN conditions. Tell them to log out of LuCI and back in to see the Mesh page.
11. **Clean up:** `rm -f /tmp/meshkeeper-*.apk /tmp/luci-app-meshkeeper-*.apk /tmp/wpad-swap.log`. `/tmp` is RAM.

## Rollback

`apk del luci-app-meshkeeper meshkeeper`, restore the backup with `scp -O ./wireless.backup root@<gw>:/etc/config/wireless` and a detached `wifi reload` (step 9), and if they want the basic wpad back, the step 7 swap the other way round.
