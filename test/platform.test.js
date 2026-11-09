import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import { osFamilyOfCriteria } from '../utils/platform.js';
import database from '../utils/database.js';

describe('osFamilyOfCriteria', () => {
	const CASES = [
		['cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*', 'windows'],
		['cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*', 'windows'],
		['cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', 'linux'],
		['cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*', 'linux'],
		['cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*', 'linux'],
		['cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*', 'linux'],
		['cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*', 'macos'],
		['cpe:2.3:h:netapp:a250:-:*:*:*:*:*:*:*', undefined],
		['cpe:2.3:a:gnu:gnutls:*:*:*:*:*:*:*:*', undefined],
		['cpe:2.3:o:netapp:a250_firmware:-:*:*:*:*:*:*:*', undefined]
	];
	for (const [criteria, family] of CASES) {
		it(`${criteria} => ${family}`, () => assert.equal(osFamilyOfCriteria(criteria), family));
	}
});

describe('platform conditions in machine vulnerabilities', () => {
	const CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';
	let server;
	let token;
	before(async () => { server = await startServer(); });
	after(() => server.close());

	const machines = {};
	beforeEach(async () => {
		await reset();
		({ accessToken: token } = await createSignedInUser(server.baseUrl));
		for (const [hostname, osFamily] of [['lin-01', 'linux'], ['win-01', 'windows'], ['unk-01', 'linux']]) {
			const { body } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname } });
			machines[hostname] = body.machineID;
			await api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': body.apiKey }, body: { osFamily, software: [{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }] } });
		}
		await database.query('UPDATE machines SET osFamily = NULL WHERE hostname = ?', ['unk-01']); // agent never reported its OS
		await database.query('UPDATE software_cpe SET status = ?, cpeName = ?', ['matched', CPE]);
		const links = [
			['CVE-2000-0010', '["cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"]'],
			['CVE-2000-0020', ''],
			['CVE-2000-0030', '["cpe:2.3:h:acme:appliance:-:*:*:*:*:*:*:*"]']
		];
		for (const [cveID, platforms] of links) {
			await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, 7.5, ?)', [cveID, 'HIGH']);
			await database.query("INSERT INTO cpe_cve (cpeName, cveID, platforms) VALUES (?, ?, NULLIF(?, ''))", [CPE, cveID, platforms]);
		}
	});

	const flags = async hostname => {
		const { body } = await api(server.baseUrl, 'GET', `/machines/${machines[hostname]}/vulns`, { token });
		return body.vulnerabilities.map(({ cveID, platformDependent }) => `${cveID}:${platformDependent}`);
	};

	it('drops a Windows-only CVE on a Linux machine', async () => {
		assert.deepEqual(await flags('lin-01'), ['CVE-2000-0020:false', 'CVE-2000-0030:true']);
	});

	it('keeps it, flagged, on a Windows machine', async () => {
		assert.deepEqual(await flags('win-01'), ['CVE-2000-0010:true', 'CVE-2000-0020:false', 'CVE-2000-0030:true']);
	});

	it('keeps every conditional CVE, flagged, when the machine OS is unknown', async () => {
		assert.deepEqual(await flags('unk-01'), ['CVE-2000-0010:true', 'CVE-2000-0020:false', 'CVE-2000-0030:true']);
	});
});
