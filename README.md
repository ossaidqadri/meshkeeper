# meshkeeper

A tiny EasyMesh (Multi-AP) controller for OpenWrt. It lets a stock-firmware mesh satellite, like a TP-Link Archer AX12, hang off an OpenWrt main router over Wi-Fi, take the router's network names and passwords, and come back on its own after a power cut with one button press on the satellite.

One static binary, about 780 KB, about 1 MB of RAM. Written in Zig, no runtime dependencies beyond what OpenWrt already has.

## Why

My main router used to be a TP-Link Archer AX12. I wanted OpenWrt running the network, and the AX12 has no OpenWrt port, so my older Archer C6 v2 took over as the main router and the AX12 moved to satellite duty over Wi-Fi. Its stock firmware speaks EasyMesh. OpenWrt can onboard it over WPS, but there's no controller, so the satellite keeps broadcasting its factory network names and never gets yours. The full open-source controllers (prplMesh, iopsys mapcontroller) are far too big for a router with 3 MB of free flash. meshkeeper does just the part a home setup needs.

## What we ran into, and how it's handled

### The satellite never rejoins after a power cut

This was the big one. After any reboot or Wi-Fi restart of the AX12 it boots, broadcasts its networks with no uplink, and sends probe requests every 10 seconds, but never actually connects back. Hidden backhaul or visible, controller running or not, didn't matter. The only thing that brings it back is a WPS press on the satellite while the router's WPS window is open.

So meshkeeper watches for exactly that state. When a known satellite has gone quiet on the mesh for 60 seconds and its backhaul radio has been probing for another 60, it opens the router's WPS window by itself. You walk over, press WPS on the satellite once, done. Windows are capped at 3 per outage, 150 seconds apart. Turn it off with `auto_wps '0'` if you'd rather open WPS yourself (see Security).

### Every settings push restarts the satellite's Wi-Fi

Applying an M2 (the message that carries network name and password) restarts the AX12's Wi-Fi, and per the problem above, that drops the backhaul about 40 seconds later until someone presses WPS. So meshkeeper only sends one when it has to: it reads what the satellite says it's broadcasting and keeps a hash of the credentials it last pushed. Same name, same password, nothing is sent. Change your Wi-Fi password on the router and it asks the satellite to renew once, which costs one WPS press on the satellite.

### The router keeps a dead station around

The C6's 5 GHz driver (ath10k) kept the unplugged satellite listed as connected for 7+ minutes, which gets in the way of it rejoining. meshkeeper drops that stale entry right before it opens the WPS window.

### Phantom satellites

The AX12's backhaul radio also sends zero-filled frames with the 1905 ethertype. They parse as empty messages and would turn its radio MAC into a second "satellite". Only messages a satellite sends about itself can register one now.

### Router config gotchas

Two things on the OpenWrt side, both handled by the config below rather than code. Without `wds '1'` on the backhaul network the satellite joins as a plain client and all its traffic gets dropped. And OpenWrt 25.12 won't hand out a backhaul password that is exactly 8 characters over WPS (fixed upstream in 6ac9cf15c965, not in 25.12). Using a dedicated hidden backhaul network with a long random key avoids that, and as a bonus, changing your normal Wi-Fi password no longer kicks the satellite off.

Also, never log into the satellite's own web page while it's in satellite mode. On the AX12 that flips it back to main router mode and drops the link.

## Tested on

TP-Link Archer C6 v2 (US) on OpenWrt 25.12.6 as the main router, TP-Link Archer AX12 (US) v1 on stock firmware 1.5.1 as the satellite, 5 GHz backhaul. Other EasyMesh satellites might work the same way but haven't been tried. Reports welcome.

## How it works

It listens for IEEE 1905 frames on the LAN bridge with a raw socket, answers the satellite's controller search and topology queries, and answers its per-radio M1 with an M2 built from your router's own `wireless` config (WSC: DH group 5, HMAC-SHA256 key derivation, AES-128-CBC). It reads its config files from `/etc/config`, talks to hostapd over ubus, and watches hostapd probe events for the auto-WPS check. The decision logic is a pure state machine with no I/O, so all of it is unit tested on the host. What it learns (satellite interfaces, radio bands, credential hashes, never passwords) is saved to `/etc/meshkeeper/state` only when something changes.

## Setup

### 1. Router Wi-Fi

You need the full `wpad-mbedtls` (or another full wpad), not `wpad-basic`, for WPS. Then add a hidden backhaul network on the radio the satellite will connect to, and point your 5 GHz network's WPS at it:

```
config wifi-iface 'meshbh'
	option device 'radio0'
	option mode 'ap'
	option network 'lan'
	option ssid 'bh-<8 random characters>'
	option hidden '1'
	option encryption 'psk2'
	option key '<32 random characters>'
	option multi_ap '1'
	option wds '1'

config wifi-iface 'wifinet1'
	# your normal 5 GHz network
	option multi_ap '2'
	option wps_pushbutton '1'
	option multi_ap_backhaul_ssid 'bh-<same as above>'
	option multi_ap_backhaul_key '<same as above>'
```

Generate the SSID and key on the router, e.g. `tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32`, and check they're not empty before you apply. Then `wifi reload`.

### 2. Install

From a machine with the binary built (see Building) and this repo:

```
scp -O zig-out/bin/meshkeeper root@192.168.1.1:/usr/sbin/meshkeeper
scp -O files/etc/config/meshkeeper root@192.168.1.1:/etc/config/meshkeeper
scp -O files/etc/init.d/meshkeeper root@192.168.1.1:/etc/init.d/meshkeeper
scp -O files/etc/capabilities/meshkeeper.json root@192.168.1.1:/etc/capabilities/meshkeeper.json
scp -O files/usr/share/acl.d/meshkeeper.json root@192.168.1.1:/usr/share/acl.d/meshkeeper.json
ssh root@192.168.1.1 'chmod 755 /usr/sbin/meshkeeper /etc/init.d/meshkeeper && /etc/init.d/meshkeeper enable && /etc/init.d/meshkeeper start'
```

To keep it across firmware upgrades, add these to `/etc/sysupgrade.conf`:

```
/usr/sbin/meshkeeper
/etc/init.d/meshkeeper
/etc/rc.d/S99meshkeeper
/etc/capabilities/meshkeeper.json
/usr/share/acl.d/meshkeeper.json
/etc/meshkeeper/
```

`logread -e meshkeeper` shows what it's doing.

Optional, if you use LuCI: a Status, Mesh page that lists every wireless device, which router it's on and how well that router hears it, refreshed every 5 seconds. Handy while you find a spot for the satellite.

```
ssh root@192.168.1.1 'mkdir -p /www/luci-static/resources/view/meshkeeper'
scp -O files/www/luci-static/resources/view/meshkeeper/mesh.js root@192.168.1.1:/www/luci-static/resources/view/meshkeeper/mesh.js
scp -O files/usr/share/luci/menu.d/luci-app-meshkeeper.json root@192.168.1.1:/usr/share/luci/menu.d/luci-app-meshkeeper.json
scp -O files/usr/share/rpcd/acl.d/luci-app-meshkeeper.json root@192.168.1.1:/usr/share/rpcd/acl.d/luci-app-meshkeeper.json
ssh root@192.168.1.1 '/etc/init.d/rpcd reload'
```

Then log out of LuCI and back in, permissions are read at login. Add those three files to `/etc/sysupgrade.conf` too.

### 3. Pair the satellite once

Put the satellite in EasyMesh satellite mode using its own web page (on the AX12: Advanced, EasyMesh, Change Mode, Satellite Router). After it reboots, open WPS on the router's 5 GHz network (`ubus call hostapd.phy0-ap0 wps_start`, your interface name may differ) and short press WPS on the satellite. Within a minute or two meshkeeper pushes your network names, with the suffix you configured. Each radio's first push restarts the satellite's Wi-Fi, so expect up to two more WPS presses on the satellite during first setup. With auto-WPS on, the router side opens by itself.

### Configuration

`/etc/config/meshkeeper`:

```
config controller 'main'
	# Bridge the agents' 1905 frames arrive on.
	option interface 'br-lan'
	# Wireless sections whose SSID and key the agents' 2.4 and 5 GHz radios copy.
	option fronthaul_2g 'wifinet0'
	option fronthaul_5g 'wifinet1'
	# Appended to the copied SSIDs, e.g. ' Ext'; empty for one shared name.
	option ssid_suffix ' Ext'
	# Open the router's WPS window when a known satellite lost power and is
	# searching (see README for the security trade-off).
	option auto_wps '1'
	# Suggest a better router to clients (802.11v): '1' on, 'log' measures
	# but never moves, only logs what it would do. Needs one shared name
	# (ssid_suffix ''), since clients only move between BSSes of one network.
	option steering '0'
```

With `steering '1'`, a device on the satellite's 5 GHz that the satellite hears below -65 dBm gets asked, once a minute, how it hears both routers (802.11k, through the satellite); if the router is at least 10 dB better it gets asked to move there. A device on the router's 5 GHz that stays below -75 dBm for 20 seconds gets the satellite suggested. `steering 'log'` measures the same way and makes the same decisions but never moves a device, only logs what it would do, a safe way to see it first. It's a suggestion, never a kick: the device can say no. Each device is moved at most once every 5 minutes so it can't bounce, and every time it says no that wait doubles, up to 80 minutes. Devices that don't support 802.11v aren't asked. The satellite can't measure devices it isn't serving, so the second direction relies on the device's own scan. While steering is on, the router's 5 GHz and 2.4 GHz networks announce 802.11v support until the next Wi-Fi reload, when meshkeeper turns it back on.

Set `fronthaul_2g` and `fronthaul_5g` to your own wireless section names. A fresh OpenWrt usually has `default_radio0` and `default_radio1`, and `uci show wireless | grep =wifi-iface` lists yours. With a wrong name it logs "wireless section not found" and pushes nothing. The sections need a name; an anonymous `config wifi-iface` can't be picked.

Run `meshkeeper --observe` to watch the traffic without sending anything, opening WPS or writing to flash.

## Security

It runs as its own `meshkeeper` user inside ujail, with only `CAP_NET_RAW` and no way to gain more. It reads its own config and `wireless` straight from `/etc/config` as that user, so the root-only configs (network with your WAN login, system, dhcp, uhttpd, rpcd, dropbear) stay out of its reach. `wireless` is readable by every user on stock OpenWrt anyway. Over ubus it can only read the wireless status and call seven hostapd methods (`notify_response`, `del_client`, `wps_start`, and for steering `get_status`, `get_clients`, `bss_mgmt_enable`, `bss_transition_request`), nothing else. Parsers never trust a length field and are fuzz tested, and release binaries keep Zig's safety checks on, so a bad frame is an error or a clean restart by procd, not memory corruption.

The honest trade-off is auto-WPS. Its trigger is a probe request from the satellite's backhaul MAC, and anyone nearby can fake a MAC. On its own that isn't enough: the real satellite also has to stop talking on the LAN for a minute, which takes a power cut or jamming. But if someone pulls that off, the router opens WPS and any device that presses its own WPS button inside those 2 minutes joins your Wi-Fi, which means LAN access. If that's not a risk you want, set `auto_wps '0'` and open WPS by hand after a power cut.

## Building

Needs Zig 0.17.

```
zig build test
zig build -Dtarget=mips-linux-musleabi -Dcpu=mips32r2 -Drelease
```

The second line gives `zig-out/bin/meshkeeper` for ath79 (MIPS 24Kc). Change the target for your router's CPU. Safety checks stay on in release, on purpose.

`prototype/` is the Python version that first proved the AX12 accepts a non-TP-Link controller. Its M2 builder is what the satellite accepted, so the Zig side is tested byte for byte against vectors it generates (`cd prototype && uv run python gen_vectors.py`).

## Limits

One satellite tested, 5 GHz backhaul only, up to 4 satellites in the table. Multi-AP profile 1, steering between routers but not between bands, and the satellite's networks get WPA2. Messages that need fragmenting aren't supported, none of the ones the AX12 sends did.

## License

MIT, see [LICENSE](LICENSE).

Wi-Fi EasyMesh is a trademark of Wi-Fi Alliance. meshkeeper isn't certified or affiliated with them, or with TP-Link.
