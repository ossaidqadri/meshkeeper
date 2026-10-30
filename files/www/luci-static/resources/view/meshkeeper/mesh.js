'use strict';
'require view';
'require fs';
'require network';
'require poll';

// Which device sits on which router, and how well that router hears it.
// Main router clients come from iwinfo; satellite clients from the file
// meshkeeper rewrites every 5 s.

const MESH_FILE = '/var/run/meshkeeper/mesh.json';

function signalText(dbm) {
	if (dbm == null)
		return _('measuring…');
	const word = dbm >= -65 ? _('good') : dbm >= -75 ? _('fair') : _('weak');
	return '%d dBm (%s)'.format(dbm, word);
}

function satelliteName(agents, i) {
	return agents.length > 1 ? _('Satellite %d').format(i + 1) : _('Satellite');
}

// `links`: satellite backhaul MAC to the signal the main router hears from it,
// the number that matters when placing the satellite.
function statusText(mesh, links) {
	if (!mesh)
		return _('meshkeeper is not running, devices on the satellite are not shown.');
	if (!mesh.agents.length)
		return _('No satellite has joined yet.');
	return mesh.agents.map((a, i) => {
		const link = a.ifaces.map(m => links.get(m)).find(s => s != null);
		const state = !a.online ? _('offline')
			: link == null ? _('online') : _('online, link to main router %s').format(signalText(link));
		return '%s: %s'.format(satelliteName(mesh.agents, i), state);
	}).join('. ');
}

return view.extend({
	load() {
		return Promise.all([
			L.resolveDefault(fs.read(MESH_FILE).then(JSON.parse), null),
			network.getWifiNetworks().then(nets => Promise.all(nets.map(net =>
				L.resolveDefault(net.getAssocList(), [])))),
			network.getHostHints()
		]);
	},

	update(status, table, [mesh, local, hints]) {
		const agents = mesh ? mesh.agents : [];
		// A satellite's own backhaul link shows up as a main router client; skip it.
		const backhaul = new Set(agents.flatMap(a => a.ifaces));
		const name = mac => hints.getHostnameByMACAddr(mac) || mac;
		const links = new Map();
		const rows = [];

		for (const sta of local.flat())
			if (backhaul.has(sta.mac.toLowerCase()))
				links.set(sta.mac.toLowerCase(), sta.signal);
			else
				rows.push([ name(sta.mac), _('Main router'), signalText(sta.signal),
					'%d / %d Mbit/s'.format(sta.tx.rate / 1000, sta.rx.rate / 1000) ]);

		agents.forEach((a, i) => {
			if (!a.online)
				return; // its client list is stale until it reports again
			for (const c of a.clients)
				rows.push([ name(c.mac.toUpperCase()), satelliteName(agents, i), signalText(c.rssi),
					c.rssi == null ? '-' : '%d / %d Mbit/s'.format(c.down_mbps, c.up_mbps) ]);
		});

		status.textContent = statusText(mesh, links);
		cbi_update_table(table, rows, E('em', _('No wireless devices connected')));
	},

	render(data) {
		const status = E('p');
		const table = E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Device')),
				E('th', { 'class': 'th' }, _('Connected to')),
				E('th', { 'class': 'th' }, _('Signal (as that router hears it)')),
				E('th', { 'class': 'th' }, _('Speed down / up'))
			])
		]);

		this.update(status, table, data);
		poll.add(() => this.load().then(d => this.update(status, table, d)), 5);

		return E([], [
			E('h2', _('Mesh')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Every wireless device and the router it is on. The satellite link and main router devices update every 5 seconds, so you can watch the link while moving the satellite. Each satellite device is measured in turn, every 10 seconds per device.')),
			status,
			table
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
