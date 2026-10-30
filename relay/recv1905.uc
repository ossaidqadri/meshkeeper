// Print every IEEE 1905 frame seen on an interface as one hex line on stdout.
// Read-only: it never sends. Exits when stdout closes.
// Usage: ucode -S recv1905.uc [interface]
'use strict';

import { create, error, AF_PACKET, SOCK_RAW } from 'socket';
import { stdout } from 'fs';

const ETH_P_1905 = 0x893a;
const PACKET_OUTGOING = 4;
const iface = ARGV[0] ?? 'br-lan';

const sock = create(AF_PACKET, SOCK_RAW, 0);
if (!sock || !sock.bind({ family: AF_PACKET, protocol: ETH_P_1905, interface: iface, address: '00:00:00:00:00:00' }))
	die(`recv1905: ${error()}\n`);

while (true) {
	let from = {};
	let frame = sock.recv(2048, 0, from);

	if (frame == null)
		die(`recv1905: ${error()}\n`);

	// Our own transmissions loop back to the packet socket; skip them.
	if (from.packet_type == PACKET_OUTGOING)
		continue;

	if (!stdout.write(hexenc(frame) + '\n') || !stdout.flush())
		exit(0);
}
