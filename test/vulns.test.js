import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser } from './helpers/fixtures.js';
import { startNvdStub, loadFixture } from './helpers/nvd-stub.js';
import { runOnce as resolveCpes } from '../jobs/resolve-cpe.js';
import { runOnce as syncCves } from '../jobs/sync-cves.js';
import { createNvdClient } from '../utils/nvd.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

const OPENSSL_CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';
const LIBSSL_CPE = 'cpe:2.3:a:debian:libssl3:3.0.0:*:*:*:*:*:*:*';

let server;
let stub;
before(async () => {
	server = await startServer();
	stub = await startNvdStub();
});
after(async () => {
	await stub.close();
	await server.close();
});

let token;
let machine;
beforeEach(async () => {
	await reset();
	stub.reset();
	({ accessToken: token } = await createSignedInUser(server.baseUrl));
	({ body: machine } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname: 'web-01' } }));
});

const push = software => api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': machine.apiKey }, body: { osFamily: 'linux', software } });
const getVulns = (id = machine.machineID) => api(server.baseUrl, 'GET', `/machines/${id}/vulns`, { token });
const mapSoftware = (name, cpeName) => database.query('UPDATE software_cpe SET status = \'matched\', cpeName = ? WHERE name = ?', [cpeName, name]);
async function seedCve(cveID, cvssScore, cpeNames) {
	await database.query('INSERT INTO cve (cveID, description, cvssScore, severity, published) VALUES (?, ?, ?, ?, \'2024-01-02 03:04:05\')', [cveID, `${cveID} description`, cvssScore, cvssScore >= 7 ? 'HIGH' : 'MEDIUM']);
	for (const cpeName of cpeNames) await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [cpeName, cveID]);
}

describe('GET /machines/:id/vulns', () => {
	it('lists the CVEs found by the NVD jobs for the installed software', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }]);
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		stub.route('/cves/2.0', OPENSSL_CPE, loadFixture('cves-openssl-3.0.0.json'));
		const client = createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1 });
		await resolveCpes({ client });
		await syncCves({ client });

		const response = await getVulns();
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.vulnerabilities.map(({ cveID }) => cveID), ['CVE-2021-4044', 'CVE-2022-0778', 'CVE-2022-3996']);
		const [first] = response.body.vulnerabilities;
		assert.equal(first.severity, 'HIGH');
		assert.equal(first.cvssScore, 7.5);
		assert.match(first.published, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
		assert.deepEqual(first.software, [{ name: 'openssl', version: '3.0.0' }]);
		assert.equal(first.versionNormalized, false);
		assert.equal(response.body.unmappedSoftware, 0);
	});

	it('flags a CVE as versionNormalized only when no exact-version software confirms it', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0-1~deb12u2' }, { name: 'libssl3', vendor: 'debian', version: '3.0.0' }]);
		await mapSoftware('openssl', OPENSSL_CPE);
		await mapSoftware('libssl3', LIBSSL_CPE);
		await database.query('UPDATE software_cpe SET versionNormalized = 1 WHERE name = ?', ['openssl']);
		await seedCve('CVE-2000-0001', 5, [OPENSSL_CPE]);
		await seedCve('CVE-2000-0002', 9.8, [OPENSSL_CPE, LIBSSL_CPE]);

		const { body } = await getVulns();
		assert.deepEqual(body.vulnerabilities.map(({ cveID, versionNormalized }) => `${cveID}:${versionNormalized}`), ['CVE-2000-0002:false', 'CVE-2000-0001:true']);
	});

	it('lists a CVE hitting 2 installed software once with both, sorted by score', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }, { name: 'libssl3', vendor: 'debian', version: '3.0.0' }]);
		await mapSoftware('openssl', OPENSSL_CPE);
		await mapSoftware('libssl3', LIBSSL_CPE);
		await seedCve('CVE-2000-0001', 5, [OPENSSL_CPE]);
		await seedCve('CVE-2000-0002', 9.8, [OPENSSL_CPE, LIBSSL_CPE]);

		const { body } = await getVulns();
		assert.deepEqual(body.vulnerabilities.map(({ cveID, cvssScore }) => `${cveID}:${cvssScore}`), ['CVE-2000-0002:9.8', 'CVE-2000-0001:5']);
		assert.deepEqual(body.vulnerabilities[0].software, [{ name: 'libssl3', version: '3.0.0' }, { name: 'openssl', version: '3.0.0' }]);
	});

	it('returns an empty list for a machine whose software has no CVE', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }]);
		await mapSoftware('openssl', OPENSSL_CPE);
		const response = await getVulns();
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.vulnerabilities, []);
		assert.equal(response.body.unmappedSoftware, 0);
	});

	it('counts pending and unmatched software under unmappedSoftware', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }, { name: 'curl', version: '8.0' }, { name: 'tool', version: '1' }]);
		await mapSoftware('openssl', OPENSSL_CPE);
		await database.query('UPDATE software_cpe SET status = \'unmatched\', lastCheckedAt = UTC_TIMESTAMP() WHERE name = \'curl\'');
		const { body } = await getVulns();
		assert.equal(body.unmappedSoftware, 2);
	});

	it('only reflects the latest snapshot', async () => {
		await push([{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }]);
		await mapSoftware('openssl', OPENSSL_CPE);
		await seedCve('CVE-2000-0001', 5, [OPENSSL_CPE]);
		await push([{ name: 'curl', version: '8.0' }]);
		const { body } = await getVulns();
		assert.deepEqual(body.vulnerabilities, []);
		assert.equal(body.unmappedSoftware, 1);
	});

	it('answers 404 for an unknown machine, 400 for a bad id, 401 without token', async () => {
		const unknown = await getVulns(999_999);
		assert.equal(unknown.status, 404);
		const invalid = await getVulns('abc');
		assert.equal(invalid.status, 400);
		const anonymous = await api(server.baseUrl, 'GET', `/machines/${machine.machineID}/vulns`);
		assert.equal(anonymous.status, 401);
	});
});
