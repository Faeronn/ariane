import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, createOrganization } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset, TEST_ORG_ID } from './helpers/database.js';
import database from '../utils/database.js';

const OPENSSL = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';
const CURL = 'cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let viewer;
let otherOrgID;
// Org Test: web-01 (openssl + curl, seen now), web-02 (openssl, never seen: stale), web-03 revoked
// (openssl). Org Other: one machine with openssl. CVEs: A CRITICAL on openssl, B MEDIUM on curl.
beforeEach(async () => {
	await reset();
	otherOrgID = await createOrganization('Other', 'other.test');
	await createSignedInUser(server.baseUrl, 'alice');
	viewer = await createSignedInUser(server.baseUrl, 'bob');

	const machines = [[1, TEST_ORG_ID, 'web-01', 'UTC_TIMESTAMP()', 'NULL', ['openssl', 'curl']], [2, TEST_ORG_ID, 'web-02', 'NULL', 'NULL', ['openssl']], [3, TEST_ORG_ID, 'web-03', 'UTC_TIMESTAMP()', 'UTC_TIMESTAMP()', ['openssl']], [4, otherOrgID, 'x-01', 'UTC_TIMESTAMP()', 'NULL', ['openssl']]];
	for (const [machineID, orgID, hostname, lastSeenAt, revokedAt, software] of machines) {
		await database.query(`INSERT INTO machines (machineID, orgID, hostname, apiKeyHash, createdAt, lastSeenAt, revokedAt, osFamily) VALUES (?, ?, ?, SHA2(?, 256), UTC_TIMESTAMP(), ${lastSeenAt}, ${revokedAt}, 'linux')`, [machineID, orgID, hostname, hostname]);
		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())', [machineID, machineID]);
		for (const name of software) await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (?, '', ?, ?)", [machineID, name, name === 'curl' ? '8.0' : '3.0.0']);
	}
	await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (1, '', 'mystery', '1')");
	await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status) VALUES ('', 'openssl', '3.0.0', ?, 'matched'), ('', 'curl', '8.0', ?, 'matched')", [OPENSSL, CURL]);
	for (const [cveID, score, severity, cpe] of [['CVE-A', 9.8, 'CRITICAL', OPENSSL], ['CVE-B', 5, 'MEDIUM', CURL]]) {
		await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, ?, ?)', [cveID, score, severity]);
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [cpe, cveID]);
	}
});

describe('GET /fleet/summary', () => {
	it('summarizes the organization fleet for any member', async () => {
		const response = await api(server.baseUrl, 'GET', '/fleet/summary', { token: viewer.accessToken });
		assert.equal(response.status, 200);
		const { machines, vulnerabilities, unmappedSoftware } = response.body;
		assert.deepEqual(machines, { total: 3, active: 2, revoked: 1, stale: 1 });
		assert.deepEqual(vulnerabilities.bySeverity, { CRITICAL: 1, HIGH: 0, MEDIUM: 1, LOW: 0, UNKNOWN: 0 });
		assert.equal(vulnerabilities.total, 2);
		assert.equal(vulnerabilities.affectedMachines, 2);
		assert.deepEqual(vulnerabilities.topCves.map(({ cveID, machines: count }) => `${cveID}:${count}`), ['CVE-A:2', 'CVE-B:1']);
		assert.equal(unmappedSoftware, 1);
	});

	it('answers zeros for an organization without machines', async () => {
		await createOrganization('Empty', 'empty.test');
		const carol = await createSignedInUser(server.baseUrl, 'carol', 'empty.test');
		const { status, body } = await api(server.baseUrl, 'GET', '/fleet/summary', { token: carol.accessToken });
		assert.equal(status, 200);
		assert.deepEqual(body.machines, { total: 0, active: 0, revoked: 0, stale: 0 });
		assert.deepEqual(body.vulnerabilities, { total: 0, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 }, affectedMachines: 0, topCves: [] });
		assert.equal(body.unmappedSoftware, 0);
	});

	it('requires a token', async () => {
		const response = await api(server.baseUrl, 'GET', '/fleet/summary');
		assert.equal(response.status, 401);
	});
});
