import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import { machineVulnerabilities, countUnmapped } from '../utils/vulnerabilities.js';
import database from '../utils/database.js';

const OPENSSL_CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let token;
let machineID;
beforeEach(async () => {
	await reset();
	({ accessToken: token } = await createSignedInUser(server.baseUrl));
	const { body } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname: 'web-01' } });
	machineID = body.machineID;
	await api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': body.apiKey }, body: { osFamily: 'linux', software: [{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }, { name: 'curl', version: '8.0' }] } });
	await database.query('UPDATE software_cpe SET status = ?, cpeName = ? WHERE name = ?', ['matched', OPENSSL_CPE, 'openssl']);
	for (const [cveID, score] of [['CVE-2000-0001', 5], ['CVE-2000-0002', 9.8]]) {
		await database.query('INSERT INTO cve (cveID, cvssScore, severity, published) VALUES (?, ?, ?, ?)', [cveID, score, score > 7 ? 'CRITICAL' : 'MEDIUM', '2024-01-02 03:04:05']);
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [OPENSSL_CPE, cveID]);
	}
});

describe('machineVulnerabilities', () => {
	it('returns the CVEs of the latest snapshot without HTTP, highest score first', async () => {
		const vulnerabilities = await machineVulnerabilities(machineID);
		assert.deepEqual(vulnerabilities.map(({ cveID, cvssScore }) => `${cveID}:${cvssScore}`), ['CVE-2000-0002:9.8', 'CVE-2000-0001:5']);
		assert.deepEqual(vulnerabilities[0].software, [{ name: 'openssl', version: '3.0.0' }]);
		assert.equal(await countUnmapped(machineID), 1);
	});

	it('gives the route the same answer', async () => {
		const { body } = await api(server.baseUrl, 'GET', `/machines/${machineID}/vulns`, { token });
		assert.deepEqual(body, { message: 'Vulnerabilities retrieved.', vulnerabilities: await machineVulnerabilities(machineID), unmappedSoftware: 1 });
	});
});
