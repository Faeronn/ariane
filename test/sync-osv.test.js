import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { startOsvStub } from './helpers/osv-stub.js';
import { runOnce, storedID, scoreOf } from '../jobs/sync-osv.js';
import { createOsvClient } from '../utils/osv.js';
import { captureLogs } from './helpers/fixtures.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

let stub;
let client;
before(async () => {
	stub = await startOsvStub();
	client = createOsvClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 500, retries: 1 });
});
after(async () => {
	await stub.close();
	await database.end();
});

const KEYS = [['npm', 'express', '4.17.1'], ['PyPI', 'requests', '2.25.0'], ['npm', 'left-pad', '1.3.0']];
beforeEach(async () => {
	await reset();
	stub.reset();
	await database.batch('INSERT INTO package_vuln_key (ecosystem, name, version) VALUES (?, ?, ?)', KEYS);
});

const links = (ecosystem, name) => database.query('SELECT cveID FROM package_vuln WHERE ecosystem = ? AND name = ? ORDER BY cveID', [ecosystem, name]).then(rows => rows.map(({ cveID }) => cveID));
const statuses = () => database.query('SELECT name, status FROM package_vuln_key ORDER BY name').then(rows => rows.map(({ name, status }) => `${name}:${status}`));

describe('sync-osv runOnce', () => {
	it('links each package to its vulnerabilities, stored under their CVE (real express 4.17.1)', async () => {
		const summary = await runOnce({ client });
		assert.deepEqual(await links('npm', 'express'), ['CVE-2024-29041', 'CVE-2024-43796']);
		assert.deepEqual(await statuses(), ['express:checked', 'left-pad:checked', 'requests:checked']);
		assert.equal(summary.checked, 3);

		const [cve] = await database.query('SELECT cvssScore, severity, description FROM cve WHERE cveID = ?', ['CVE-2024-29041']);
		assert.deepEqual({ cvssScore: Number(cve.cvssScore), severity: cve.severity }, { cvssScore: 6.1, severity: 'MEDIUM' });
		assert.match(cve.description, /Express/i);
	});

	it('merges the advisories of one CVE and keeps an advisory without CVE under its own id', async () => {
		stub.setIds('PyPI:requests@2.25.0', ['PYSEC-2023-74', 'GHSA-j8r2-6x86-q33q', 'GHSA-no-cve']);
		stub.setVuln({ id: 'GHSA-j8r2-6x86-q33q', aliases: ['CVE-2023-32681', 'PYSEC-2023-74'], summary: 'Unintended leak of Proxy-Authorization header' });
		stub.setVuln({ id: 'GHSA-no-cve', summary: 'No CVE yet', database_specific: { severity: 'HIGH' } });
		await runOnce({ client });
		assert.deepEqual(await links('PyPI', 'requests'), ['CVE-2023-32681', 'GHSA-no-cve']);
		const [unscored] = await database.query('SELECT cvssScore, severity FROM cve WHERE cveID = ?', ['GHSA-no-cve']);
		assert.deepEqual({ ...unscored }, { cvssScore: null, severity: 'HIGH' }); // eslint-disable-line unicorn/no-null -- the driver reads SQL NULL as null
	});

	it('never overwrites a vulnerability stored from NVD', async () => {
		await database.query("INSERT INTO cve (cveID, description, cvssScore, severity) VALUES ('CVE-2024-29041', 'from NVD', 6.1, 'MEDIUM')");
		await runOnce({ client });
		const [cve] = await database.query('SELECT description FROM cve WHERE cveID = ?', ['CVE-2024-29041']);
		assert.equal(cve.description, 'from NVD');
		assert.deepEqual(await links('npm', 'express'), ['CVE-2024-29041', 'CVE-2024-43796']);
	});

	it('does not query again within 24 h nor fetch a known record twice', async () => {
		await runOnce({ client });
		const first = stub.requests.length;
		const idle = await runOnce({ client });
		assert.equal(idle.checked, 0);
		assert.equal(stub.requests.length, first);

		await database.query("UPDATE package_vuln_key SET checkedAt = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 25 HOUR)");
		const refreshed = await runOnce({ client });
		assert.deepEqual({ checked: refreshed.checked, fetched: refreshed.fetched }, { checked: 3, fetched: 0 });
	});

	it('skips an advisory OSV no longer has and links the others', async () => {
		stub.setIds('npm:express@4.17.1', ['GHSA-rv95-896h-c2vc', 'GHSA-withdrawn']);
		const summary = await runOnce({ client });
		assert.equal(summary.failed, 0);
		assert.deepEqual(await links('npm', 'express'), ['CVE-2024-29041']);
	});

	it('survives an OSV outage: no link written, keys stay pending', async () => {
		stub.failNext(503, 10);
		const logs = captureLogs();
		let summary;
		try {
			summary = await runOnce({ client });
		} finally {
			logs.restore();
		}
		assert.equal(summary.failed, 1);
		assert.deepEqual(await statuses(), ['express:pending', 'left-pad:pending', 'requests:pending']);
		const [{ count }] = await database.query('SELECT COUNT(*) AS count FROM package_vuln');
		assert.equal(Number(count), 0);
	});
});

describe('OSV record rules', () => {
	it('stores a record under its only CVE, else under its own id', () => {
		assert.equal(storedID({ id: 'GHSA-a', aliases: ['CVE-2024-1'] }), 'CVE-2024-1');
		assert.equal(storedID({ id: 'GHSA-b', aliases: ['CVE-2024-1', 'CVE-2024-2'] }), 'GHSA-b');
		assert.equal(storedID({ id: 'PYSEC-1' }), 'PYSEC-1');
	});

	it('scores from the CVSS v3 vector, else keeps the advisory band', () => {
		assert.deepEqual(scoreOf({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), { cvssScore: 9.8, severity: 'CRITICAL' });
		assert.deepEqual(scoreOf({ severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N' }], database_specific: { severity: 'MODERATE' } }), { cvssScore: undefined, severity: 'MEDIUM' });
		assert.deepEqual(scoreOf({}), { cvssScore: undefined, severity: undefined });
	});
});
