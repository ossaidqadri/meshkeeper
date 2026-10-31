# meshkeeper

A tiny EasyMesh (Multi-AP) controller for OpenWrt. It lets a stock-firmware satellite like the TP-Link Archer AX12 join an OpenWrt main router over Wi-Fi, take the router's network names and passwords, and rejoin by itself after a power cut with one WPS press on the satellite.

One static Zig binary with no runtime dependencies beyond OpenWrt.

Background and internals: [why it exists and how it works](docs/design.md), [what we ran into](docs/field-notes.md), [building](docs/building.md).

## Tested on

TP-Link Archer C6 v2 (US) on OpenWrt 25.12.6 as the main router, TP-Link Archer AX12 (US) v1 on stock firmware 1.5.1 as the satellite, 5 GHz backhaul. Other EasyMesh satellites might work but haven't been tried. Reports welcome.

## Setup

### 1. Router Wi-Fi

WPS needs a full wpad, not `wpad-basic`: `apk del wpad-basic-mbedtls && apk add wpad-mbedtls && /etc/init.d/wpad restart`. Add a hidden backhaul network on the radio the satellite will use, and point your 5 GHz network's WPS at it:

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

Generate the SSID and key on the router, e.g. `tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32`, check they're not empty, then `wifi reload`.

Keep `wds '1'`: without it the satellite joins as a plain client and its traffic is dropped. Keep the key long: OpenWrt 25.12 won't hand out an 8-character backhaul password over WPS. A separate backhaul network also means changing your normal Wi-Fi password doesn't kick the satellite off.

### 2. Install

Take the apk for your router's CPU from the release page (`apk --print-arch` shows it):

```
apk add --allow-untrusted ./meshkeeper-<version>-<arch>.apk
```

It creates the `meshkeeper` user, installs the service and starts it. `logread -e meshkeeper` shows what it's doing.

Optional, for LuCI: a Status, Mesh page listing every wireless device, which router it's on and how well that router hears it, refreshed every 5 seconds. Handy for finding a spot for the satellite. Log out of LuCI and back in afterwards, permissions are read at login.

```
apk add --allow-untrusted ./luci-app-meshkeeper-<version>.apk
```

### 3. Pair the satellite once

Put the satellite in EasyMesh satellite mode from its own web page (AX12: Advanced, EasyMesh, Change Mode, Satellite Router). After it reboots, open WPS on the router's 5 GHz network (`ubus call hostapd.phy0-ap0 wps_start`, your interface name may differ) and short press WPS on the satellite. Within a minute or two meshkeeper pushes your network names plus the suffix you configured. Each radio's first push restarts the satellite's Wi-Fi, so expect up to two more WPS presses during first setup (with `auto_wps` on, the router side opens by itself).

Don't log into the satellite's own web page afterwards: on the AX12 that flips it back to router mode and drops the link.

## Configuration

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
	# searching. Trade-off: a spoofed satellite MAC plus a jammed satellite
	# opens WPS for 2 minutes. '0' to open WPS by hand instead.
	option auto_wps '1'
	# Suggest a better router to clients (802.11v): '1' on, 'log' only logs
	# what it would do. Needs one shared name (ssid_suffix ''), since clients
	# only move between BSSes of one network.
	option steering '0'
```

Set `fronthaul_2g` and `fronthaul_5g` to your own wireless section names. A fresh OpenWrt usually has `default_radio0` and `default_radio1`; `uci show wireless | grep =wifi-iface` lists yours. A wrong name logs "wireless section not found" and pushes nothing. Anonymous `config wifi-iface` sections can't be picked, they need a name.

How steering decides: [docs/design.md](docs/design.md#steering).

`meshkeeper --observe` watches the traffic without sending anything, opening WPS or writing to flash.

## Limits

One satellite tested, 5 GHz backhaul only, up to 4 satellites in the table. Multi-AP profile 1, steering between routers but not between bands, WPA2 on the satellite's networks. Messages that need fragmenting aren't supported; none the AX12 sends do.

## License

MIT, see [LICENSE](LICENSE).

Wi-Fi EasyMesh is a trademark of Wi-Fi Alliance. meshkeeper isn't certified or affiliated with them, or with TP-Link.
