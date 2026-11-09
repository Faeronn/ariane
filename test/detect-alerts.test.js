import { describe, it, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { runOnce } from '../jobs/detect-alerts.js';
import { reset, TEST_ORG_ID } from './helpers/database.js';
import database from '../utils/database.js';

const CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';

after(() => database.end());

// One active machine whose latest snapshot runs openssl 3.0.0 (2 CVEs) and a revoked one.
beforeEach(async () => {
	await reset();
	await database.query(`INSERT INTO machines (machineID, orgID, hostname, apiKeyHash, createdAt, osFamily) VALUES (1, ?, 'm1', REPEAT('a', 64), UTC_TIMESTAMP(), 'linux')`, [TEST_ORG_ID]);
	await database.query(`INSERT INTO machines (machineID, orgID, hostname, apiKeyHash, createdAt, revokedAt) VALUES (2, ?, 'm2', REPEAT('b', 64), UTC_TIMESTAMP(), UTC_TIMESTAMP())`, [TEST_ORG_ID]);
	for (const machineID of [1, 2]) {
		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())', [machineID, machineID]);
		await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (?, 'openssl', 'openssl', '3.0.0')", [machineID]);
	}
	await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status) VALUES ('openssl', 'openssl', '3.0.0', ?, 'matched')", [CPE]);
	for (const cveID of ['CVE-2000-0001', 'CVE-2000-0002']) {
		await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, 9.8, ?)', [cveID, 'CRITICAL']);
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [CPE, cveID]);
	}
});

const state = () => database.query('SELECT machineID, cveID, resolvedAt IS NOT NULL AS resolved, emailSentAt IS NOT NULL AS emailed, webhookSentAt IS NOT NULL AS posted FROM machine_cve_state ORDER BY machineID, cveID')
	.then(rows => rows.map(({ machineID, cveID, resolved, emailed, posted }) => `${machineID}:${cveID}:${resolved ? 'resolved' : 'open'}:${emailed && posted ? 'sent' : 'unsent'}`));
const afterBaseline = () => database.query('UPDATE machines SET alertsBaselineAt = UTC_TIMESTAMP()');

describe('detect-alerts', () => {
	it('records the CVEs of a first-processed machine as already sent (baseline)', async () => {
		await runOnce();
		assert.deepEqual(await state(), ['1:CVE-2000-0001:open:sent', '1:CVE-2000-0002:open:sent']);
	});

	it('leaves CVEs appearing after the baseline unsent', async () => {
		await afterBaseline();
		await runOnce();
		assert.deepEqual(await state(), ['1:CVE-2000-0001:open:unsent', '1:CVE-2000-0002:open:unsent']);
	});

	it('changes nothing on a second pass without change', async () => {
		await afterBaseline();
		await runOnce();
		const before = await database.query('SELECT * FROM machine_cve_state ORDER BY cveID');
		await runOnce();
		assert.deepEqual(await database.query('SELECT * FROM machine_cve_state ORDER BY cveID'), before);
	});

	it('resolves CVEs gone from the latest snapshot and reopens them, unsent, when they come back', async () => {
		await afterBaseline();
		await runOnce();
		await database.query("UPDATE machine_cve_state SET emailSentAt = UTC_TIMESTAMP(), webhookSentAt = UTC_TIMESTAMP()");
		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (3, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())');
		await runOnce();
		assert.deepEqual(await state(), ['1:CVE-2000-0001:resolved:sent', '1:CVE-2000-0002:resolved:sent']);

		await database.query("INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (4, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())");
		await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (4, 'openssl', 'openssl', '3.0.0')");
		await runOnce();
		assert.deepEqual(await state(), ['1:CVE-2000-0001:open:unsent', '1:CVE-2000-0002:open:unsent']);
	});

	it('ignores revoked machines and removes the state with the machine', async () => {
		await runOnce();
		const machines = await database.query('SELECT DISTINCT machineID FROM machine_cve_state');
		assert.deepEqual(machines.map(({ machineID }) => machineID), [1]);
		await database.query('DELETE FROM machines WHERE machineID = 1');
		assert.deepEqual(await state(), []);
	});
});
