import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPackagistStub } from './helpers/packagist-stub.js';
import { runOnce } from '../jobs/sync-packagist.js';
import { createPackagistClient } from '../utils/packagist.js';
import { captureLogs } from './helpers/fixtures.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

let stub;
let client;
before(async () => {
	stub = await startPackagistStub();
	client = createPackagistClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 500, retries: 1 });
});
after(async () => {
	await stub.close();
	await database.end();
});

// Versions locked in argdoc (real composer.lock) plus an npm key Packagist must ignore.
const KEYS = [['Packagist', 'symfony/mime', '7.4.19'], ['Packagist', 'symfony/http-foundation', '7.4.21'], ['npm', 'express', '4.17.1']];
beforeEach(async () => {
	await reset();
	stub.reset();
	await database.batch("INSERT INTO package_vuln_key (ecosystem, name, version, status) VALUES (?, ?, ?, 'checked')", KEYS);
});

const links = (name, source = 'packagist') => database.query('SELECT cveID FROM package_vuln WHERE name = ? AND source = ? ORDER BY cveID', [name, source]).then(rows => rows.map(({ cveID }) => cveID));

describe('sync-packagist runOnce', () => {
	it('links each Composer package to the advisories affecting its locked version (real answers)', async () => {
		const summary = await runOnce({ client });
		assert.equal(summary.checked, 2);
		assert.deepEqual(await links('symfony/mime'), ['CVE-2026-45070']); // OSV said fixed in 7.4.12, Packagist <7.4.22
		const foundation = await links('symfony/http-foundation');
		assert.ok(foundation.includes('CVE-2026-121619'));
		assert.ok(foundation.some(id => id.startsWith('PKSA-')), 'an advisory without CVE keeps its PKSA id');
		assert.deepEqual(stub.requests[0].names.toSorted(), ['symfony/http-foundation', 'symfony/mime']);
	});

	it('stores new rows with the Packagist band and title, never touching an NVD row', async () => {
		await database.query("INSERT INTO cve (cveID, description, cvssScore, severity, source) VALUES ('CVE-2026-121619', 'from NVD', 6.5, 'MEDIUM', 'nvd')");
		await runOnce({ client });
		const [nvd] = await database.query("SELECT description, source FROM cve WHERE cveID = 'CVE-2026-121619'");
		assert.deepEqual({ ...nvd }, { description: 'from NVD', source: 'nvd' });
		const [mime] = await database.query("SELECT severity, source, description FROM cve WHERE cveID = 'CVE-2026-45070'");
		assert.equal(mime.source, 'packagist');
		assert.match(mime.description, /Email Header Injection/);
	});

	it('rewrites only its own links, keeping those of OSV', async () => {
		await database.query("INSERT INTO cve (cveID, source) VALUES ('CVE-2026-45070', 'osv')");
		await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID, source) VALUES ('Packagist', 'symfony/mime', '7.4.19', 'CVE-2026-45070', 'osv')");
		await runOnce({ client });
		assert.deepEqual(await links('symfony/mime', 'osv'), ['CVE-2026-45070']);
		assert.deepEqual(await links('symfony/mime'), ['CVE-2026-45070']);
	});

	it('does nothing within 24 h, and again after', async () => {
		await runOnce({ client });
		const idle = await runOnce({ client });
		assert.equal(idle.checked, 0);
		await database.query('UPDATE package_vuln_key SET packagistCheckedAt = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 25 HOUR)');
		const refreshed = await runOnce({ client });
		assert.equal(refreshed.checked, 2);
	});

	it('survives a Packagist outage: no link written, keys still due', async () => {
		stub.failNext(503, 10);
		const logs = captureLogs();
		let summary;
		try {
			summary = await runOnce({ client });
		} finally {
			logs.restore();
		}
		assert.equal(summary.failed, 1);
		const [{ due }] = await database.query("SELECT COUNT(*) AS due FROM package_vuln_key WHERE ecosystem = 'Packagist' AND packagistCheckedAt IS NULL");
		assert.equal(Number(due), 2);
		const [{ count }] = await database.query('SELECT COUNT(*) AS count FROM package_vuln');
		assert.equal(Number(count), 0);
	});
});
