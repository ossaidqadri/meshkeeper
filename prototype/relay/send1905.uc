// Send one IEEE 1905 frame, given as hex (full Ethernet frame), on an interface.
// Refuses anything that is not ethertype 0x893a.
// Usage: ucode -S send1905.uc <hex-frame> [interface]
'use strict';

import { create, error, AF_PACKET, SOCK_RAW } from 'socket';

const ETH_P_1905 = 0x893a;
const iface = ARGV[1] ?? 'br-lan';
const frame = hexdec(ARGV[0] ?? '');

if (frame == null || length(frame) < 22 || ord(frame, 12) != 0x89 || ord(frame, 13) != 0x3a)
	die('send1905: not a 1905 frame\n');

const hex = hexenc(substr(frame, 0, 6));
let mac = [];
for (let i = 0; i < 12; i += 2)
	push(mac, substr(hex, i, 2));

const sock = create(AF_PACKET, SOCK_RAW, 0);
if (!sock || sock.send(frame, 0, { family: AF_PACKET, protocol: ETH_P_1905, interface: iface, address: join(':', mac) }) == null)
	die(`send1905: ${error()}\n`);
