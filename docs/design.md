# Design

## Why

The main router used to be an Archer AX12, which has no OpenWrt port. An older Archer C6 v2 took over as the OpenWrt main router and the AX12 became a Wi-Fi satellite. Its stock firmware speaks EasyMesh and OpenWrt can onboard it over WPS, but with no controller the satellite keeps its factory network names and never gets yours. The full controllers (prplMesh, iopsys mapcontroller) are far too big for a router with 3 MB of free flash. meshkeeper does the part a home setup needs.

## How it works

It listens for IEEE 1905 frames on the LAN bridge with a raw socket, answers the satellite's controller search and topology queries, and answers its per-radio M1 with an M2 built from the router's own `wireless` config (WSC: DH group 5, HMAC-SHA256 key derivation, AES-128-CBC). It reads `/etc/config`, talks to hostapd over ubus, and watches hostapd probe events for the auto-WPS check. The decision logic is a pure state machine with no I/O, so it's all unit tested on the host. What it learns (satellite interfaces, radio bands, credential hashes, never passwords) is saved to `/etc/meshkeeper/state` only when something changes.

## Security

It runs as its own `meshkeeper` user inside ujail with only `CAP_NET_RAW` and no way to gain more. It reads its config and `wireless` straight from `/etc/config` as that user, so the root-only configs (network with the WAN login, system, dhcp, uhttpd, rpcd, dropbear) stay out of reach; `wireless` is world-readable on stock OpenWrt anyway. Over ubus it can read the wireless status and call seven hostapd methods: `notify_response`, `del_client`, `wps_start`, and for steering `get_status`, `get_clients`, `bss_mgmt_enable`, `bss_transition_request`. Parsers never trust a length field and are fuzz tested, and release binaries keep Zig's safety checks on, so a bad frame is an error or a clean restart by procd, not memory corruption.

The trade-off is auto-WPS. Its trigger is a probe request from the satellite's backhaul MAC, and anyone nearby can fake a MAC. That alone isn't enough: the real satellite must also stop talking on the LAN for a minute, which takes a power cut or jamming. If someone manages both, the router opens WPS and any device that presses its own WPS button within those 2 minutes joins your Wi-Fi, which means LAN access. If that risk isn't acceptable, set `auto_wps '0'` and open WPS by hand after a power cut.

## Steering

With `steering '1'`, a device on the satellite's 5 GHz that the satellite hears below -65 dBm is asked once a minute how it hears both routers (802.11k, through the satellite). If the router is at least 10 dB better, it's asked to move there. A device on the router's 5 GHz that stays below -75 dBm for 20 seconds gets the satellite suggested; the satellite can't measure devices it isn't serving, so that direction relies on the device's own scan. It's a suggestion, the device can refuse, and devices without 802.11v aren't asked. Each device moves at most once every 5 minutes, and every refusal doubles the wait, up to 80 minutes. `steering 'log'` decides the same way but only logs, a safe way to try it. While steering is on, the router's 5 and 2.4 GHz networks announce 802.11v until the next Wi-Fi reload, when meshkeeper turns it back on.
