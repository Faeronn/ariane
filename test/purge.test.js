import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { runOnce } from '../jobs/purge.js';
import { connect, reset, TEST_ORG_ID } from './helpers/database.js';
import { validateConfig } from '../utils/config.js';
import database from '../utils/database.js';

const ids = rows => rows.map(row => Object.values(row)[0]);

// Machine 1: snapshots 200, 100 and 1 day old; machine 2: only one snapshot, 200 days old.
async function seed() {
	await reset();
	await database.query(`INSERT INTO machines (machineID, orgID, hostname, apiKeyHash, createdAt) VALUES (1, ?, 'm1', REPEAT('a', 64), UTC_TIMESTAMP()), (2, ?, 'm2', REPEAT('b', 64), UTC_TIMESTAMP())`, [TEST_ORG_ID, TEST_ORG_ID]);
	for (const [snapshotID, machineID, days] of [[1, 1, 200], [2, 1, 100], [3, 1, 1], [4, 2, 200]]) {
		await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (?, ?, DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY), DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))', [snapshotID, machineID, days, days]);
	}
	for (const [snapshotID, name] of [[1, 'old-only'], [2, 'shared'], [3, 'current'], [4, 'shared'], [4, 'stale']]) {
		await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (?, '', ?, '1.0')", [snapshotID, name]);
	}
	for (const [name, cpe] of [['old-only', 'cpe:x'], ['shared', 'cpe:y'], ['current', 'cpe:z'], ['stale', '']]) {
		await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status) VALUES ('', ?, '1.0', NULLIF(?, ''), 'matched')", [name, cpe]);
	}
	for (const cveID of ['CVE-1', 'CVE-2', 'CVE-3', 'CVE-9']) await database.query('INSERT INTO cve (cveID) VALUES (?)', [cveID]);
	for (const [cpe, cveID] of [['cpe:x', 'CVE-1'], ['cpe:y', 'CVE-2'], ['cpe:z', 'CVE-3']]) await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [cpe, cveID]);

	// Application of machine 1: a 200-day-old snapshot with old-pkg, the current one with cur-pkg.
	await database.query("INSERT INTO applications (applicationID, orgID, machineID, name, createdAt, lastSeenAt) VALUES (1, ?, 1, 'app', UTC_TIMESTAMP(), UTC_TIMESTAMP())", [TEST_ORG_ID]);
	for (const [snapshotID, days, name] of [[1, 200, 'old-pkg'], [2, 1, 'cur-pkg']]) {
		await database.query('INSERT INTO application_snapshot (snapshotID, applicationID, receivedAt) VALUES (?, 1, DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))', [snapshotID, days]);
		await database.query("INSERT INTO application_dependency (snapshotID, ecosystem, name, version) VALUES (?, 'npm', ?, '1.0.0')", [snapshotID, name]);
		await database.query("INSERT INTO package_vuln_key (ecosystem, name, version, status) VALUES ('npm', ?, '1.0.0', 'checked')", [name]);
	}
	// Software keys of direct dependencies: kept while a snapshot still lists the package as direct.
	await database.query("UPDATE application_dependency SET direct = 1");
	await database.query("INSERT INTO software_cpe (vendor, name, version, status, ecosystem, packageName) VALUES ('', 'old-pkg', '1.0.0', 'unmatched', 'npm', 'old-pkg'), ('', 'cur-pkg', '1.0.0', 'unmatched', 'npm', 'cur-pkg')");
	for (const [name, cveID] of [['old-pkg', 'GHSA-old'], ['cur-pkg', 'GHSA-cur']]) {
		await database.query('INSERT INTO cve (cveID) VALUES (?)', [cveID]);
		await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID) VALUES ('npm', ?, '1.0.0', ?)", [name, cveID]);
	}
}

after(() => database.end());

describe('purge', () => {
	let summary;
	before(async () => {
		await seed();
		summary = await runOnce({ retentionDays: 90 });
	});

	it('deletes old snapshots but never a machine latest one', async () => {
		assert.deepEqual(ids(await database.query('SELECT snapshotID FROM inventory_snapshot ORDER BY 1')), [3, 4]);
		assert.equal(summary.snapshots, 2);
	});

	it('keeps software keys and CVE links still used by any machine', async () => {
		assert.deepEqual(ids(await database.query('SELECT name FROM software_cpe ORDER BY 1')), ['cur-pkg', 'current', 'shared', 'stale']);
		assert.deepEqual(ids(await database.query('SELECT cpeName FROM cpe_cve ORDER BY 1')), ['cpe:y', 'cpe:z']);
	});

	it('deletes old application snapshots but never an application latest one, then their orphan packages', async () => {
		assert.deepEqual(ids(await database.query('SELECT snapshotID FROM application_snapshot')), [2]);
		assert.deepEqual(ids(await database.query('SELECT name FROM package_vuln_key')), ['cur-pkg']);
		assert.deepEqual(ids(await database.query('SELECT cveID FROM package_vuln')), ['GHSA-cur']);
	});

	it('deletes vulnerabilities neither a CPE nor a package links to', async () => {
		assert.deepEqual(ids(await database.query('SELECT cveID FROM cve ORDER BY 1')), ['CVE-2', 'CVE-3', 'GHSA-cur']);
		assert.deepEqual(summary, { snapshots: 2, applicationSnapshots: 1, softwareKeys: 2, cpeLinks: 1, packageKeys: 1, packageLinks: 1, cves: 3 });
	});

	it('never runs while another instance holds the purge lock', async () => {
		const other = await connect();
		try {
			await other.query('SELECT GET_LOCK(?, 0)', [`${process.env.DB_NAME}:purge`]);
			assert.deepEqual(await runOnce({ retentionDays: 90 }), { skipped: true });
		} finally {
			await other.end();
		}
	});

	it('rejects an invalid retention at start-up', () => {
		assert.ok(validateConfig({ SNAPSHOT_RETENTION_DAYS: '0' }).errors.some(error => error.startsWith('SNAPSHOT_RETENTION_DAYS')));
	});
});
