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
	await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status, cvesCheckedAt) VALUES ('openssl', 'openssl', '3.0.0', ?, 'matched', UTC_TIMESTAMP())", [CPE]);
	for (const cveID of ['CVE-2000-0001', 'CVE-2000-0002']) {
		await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, 9.8, ?)', [cveID, 'CRITICAL']);
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [CPE, cveID]);
	}
});

// `m1` is machine 1, `a1` application 1.
const state = () => database.query('SELECT itemType, itemID, cveID, resolvedAt IS NOT NULL AS resolved, emailSentAt IS NOT NULL AS emailed, webhookSentAt IS NOT NULL AS posted FROM item_cve_state ORDER BY itemType = "application", itemID, cveID')
	.then(rows => rows.map(({ itemType, itemID, cveID, resolved, emailed, posted }) => `${itemType[0]}${itemID}:${cveID}:${resolved ? 'resolved' : 'open'}:${emailed && posted ? 'sent' : 'unsent'}`));
const afterBaseline = () => Promise.all([
	database.query('UPDATE machines SET alertsBaselineAt = UTC_TIMESTAMP()'),
	database.query('UPDATE applications SET alertsBaselineAt = UTC_TIMESTAMP()')
]);

// One more program on machine 1's latest snapshot, its key in `status`.
const addSoftware = (name, status) => Promise.all([
	database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (1, '', ?, '1.0')", [name]),
	database.query("INSERT INTO software_cpe (vendor, name, version, status) VALUES ('', ?, '1.0', ?)", [name, status])
]);

// Application 1 "shop" on machine 1, latest snapshot with express 4.17.1; its OSV key in `status`.
async function addApplication(status, { ecosystem = 'npm', name = 'express', version = '4.17.1' } = {}) {
	await database.query("INSERT INTO applications (applicationID, orgID, machineID, name, createdAt, lastSeenAt) VALUES (1, ?, 1, 'shop', UTC_TIMESTAMP(), UTC_TIMESTAMP())", [TEST_ORG_ID]);
	await database.query('INSERT INTO application_snapshot (snapshotID, applicationID, receivedAt) VALUES (1, 1, UTC_TIMESTAMP())');
	await database.query('INSERT INTO application_dependency (snapshotID, ecosystem, name, version, direct) VALUES (1, ?, ?, ?, 0)', [ecosystem, name, version]);
	await database.query('INSERT INTO package_vuln_key (ecosystem, name, version, status) VALUES (?, ?, ?, ?)', [ecosystem, name, version, status]);
}

const linkPackage = async (cveID, name = 'express', version = '4.17.1') => {
	await database.query("INSERT IGNORE INTO cve (cveID, cvssScore, severity) VALUES (?, 6.1, 'MEDIUM')", [cveID]);
	await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID) VALUES ('npm', ?, ?, ?)", [name, version, cveID]);
};

describe('detect-alerts per item', () => {
	it('records the CVEs of a first-processed machine as already sent (baseline)', async () => {
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent']);
	});

	it('leaves CVEs appearing after the baseline unsent', async () => {
		await afterBaseline();
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:unsent', 'm1:CVE-2000-0002:open:unsent']);
	});

	it('changes nothing on a second pass without change', async () => {
		await afterBaseline();
		await runOnce();
		const before = await database.query('SELECT * FROM item_cve_state ORDER BY cveID');
		await runOnce();
		assert.deepEqual(await database.query('SELECT * FROM item_cve_state ORDER BY cveID'), before);
	});

	it('resolves CVEs gone from the latest snapshot and reopens them, unsent, when they come back', async () => {
		await afterBaseline();
		await runOnce();
		await database.query('UPDATE item_cve_state SET emailSentAt = UTC_TIMESTAMP(), webhookSentAt = UTC_TIMESTAMP()');
		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (3, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())');
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:resolved:sent', 'm1:CVE-2000-0002:resolved:sent']);

		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (4, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())');
		await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (4, 'openssl', 'openssl', '3.0.0')");
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:unsent', 'm1:CVE-2000-0002:open:unsent']);
	});

	it('ignores revoked machines', async () => {
		const summary = await runOnce();
		assert.equal(summary.items, 1);
		const items = await database.query("SELECT DISTINCT itemID FROM item_cve_state WHERE itemType = 'machine'");
		assert.deepEqual(items.map(({ itemID }) => itemID), [1]);
	});
});

describe('detect-alerts baseline readiness', () => {
	it('defers the baseline while a program key of the machine is pending', async () => {
		await addSoftware('tool', 'pending');
		const summary = await runOnce();
		assert.equal(summary.deferred, 1);
		assert.deepEqual(await state(), []);
		const [machine] = await database.query('SELECT alertsBaselineAt, alertsCheckedAt FROM machines WHERE machineID = 1');
		assert.ok(!machine.alertsBaselineAt && !machine.alertsCheckedAt, 'neither baseline nor check recorded');
	});

	it('defers it while a matched CPE has not had its CVEs synced yet', async () => {
		await database.query('UPDATE software_cpe SET cvesCheckedAt = NULL');
		const summary = await runOnce();
		assert.equal(summary.deferred, 1);
	});

	it('takes it once every key is resolved and synced, unmatched ones included', async () => {
		await addSoftware('tool', 'pending');
		await runOnce();
		await database.query("UPDATE software_cpe SET status = 'unmatched' WHERE name = 'tool'");
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent']);
	});

	it('does not wait on a machine that already has its baseline', async () => {
		await afterBaseline();
		await addSoftware('tool', 'pending');
		const summary = await runOnce();
		assert.equal(summary.deferred, 0);
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:unsent', 'm1:CVE-2000-0002:open:unsent']);
	});
});

describe('detect-alerts for applications', () => {
	it('defers only the application whose packages wait for OSV, the machine item goes on', async () => {
		await addApplication('pending');
		const summary = await runOnce();
		assert.deepEqual({ items: summary.items, deferred: summary.deferred }, { items: 1, deferred: 1 });
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent']);
	});

	it('opens a package vulnerability appearing after the baseline, on the application only', async () => {
		await addApplication('checked');
		await runOnce();
		await linkPackage('CVE-2024-29041');
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent', 'a1:CVE-2024-29041:open:unsent']);
	});

	it('takes a silent baseline for an application registered on an already monitored machine', async () => {
		await afterBaseline();
		await runOnce();
		await database.query('UPDATE item_cve_state SET emailSentAt = UTC_TIMESTAMP(), webhookSentAt = UTC_TIMESTAMP()');
		await addApplication('checked');
		await linkPackage('CVE-2024-29041');
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent', 'a1:CVE-2024-29041:open:sent']);
	});

	it('alerts a CVE already open on the machine when it appears in an application', async () => {
		await addApplication('checked');
		await runOnce();
		await linkPackage('CVE-2000-0001');
		await runOnce();
		assert.deepEqual(await state(), ['m1:CVE-2000-0001:open:sent', 'm1:CVE-2000-0002:open:sent', 'a1:CVE-2000-0001:open:unsent']);
	});

	it('defers the baseline of a Composer application until Packagist has checked its packages', async () => {
		await addApplication('checked', { ecosystem: 'Packagist', name: 'symfony/mime', version: '7.4.19' });
		const waiting = await runOnce();
		assert.equal(waiting.deferred, 1);
		await database.query('UPDATE package_vuln_key SET packagistCheckedAt = UTC_TIMESTAMP()');
		const ready = await runOnce();
		assert.equal(ready.deferred, 0);
	});
});
