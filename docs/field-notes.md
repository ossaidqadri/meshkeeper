# What we ran into

## The satellite never rejoins after a power cut

After any reboot or Wi-Fi restart the AX12 boots, broadcasts its networks with no uplink and sends probe requests every 10 seconds, but never connects back. Hidden or visible backhaul, controller running or not, makes no difference. Only a WPS press on the satellite while the router's WPS window is open brings it back.

So meshkeeper watches for that state. When a known satellite has been quiet on the mesh for 60 seconds and its backhaul radio has probed for another 60, it opens the router's WPS window itself; you press WPS on the satellite once. Windows are capped at 3 per outage, 150 seconds apart. `auto_wps '0'` turns it off (trade-off: [design.md](design.md#security)).

## Every settings push restarts the satellite's Wi-Fi

Applying an M2 (the message carrying network name and password) restarts the AX12's Wi-Fi, and per the above that drops the backhaul about 40 seconds later until someone presses WPS. So meshkeeper pushes only when it has to: it reads what the satellite broadcasts and keeps a hash of the credentials it last pushed. Same name and password, nothing is sent. Change your Wi-Fi password and it asks the satellite to renew once, costing one WPS press.

## The router keeps a dead station around

The C6's 5 GHz driver (ath10k) listed the unplugged satellite as connected for 7+ minutes, which blocks its rejoin. meshkeeper drops that stale entry just before opening the WPS window.

## Phantom satellites

The AX12's backhaul radio also sends zero-filled frames with the 1905 ethertype. They parse as empty messages and would register its radio MAC as a second satellite, so only messages a satellite sends about itself can register one.

## Router config

Without `wds '1'` on the backhaul network the satellite joins as a plain client and all its traffic is dropped. OpenWrt 25.12 won't hand out a backhaul password of exactly 8 characters over WPS (fixed upstream in 6ac9cf15c965, not in 25.12). A dedicated hidden backhaul network with a long random key avoids that, and changing your normal Wi-Fi password no longer kicks the satellite off. Both are handled by the config in the README, not by code.

Logging into the satellite's own web page while it's in satellite mode flips the AX12 back to router mode and drops the link.
