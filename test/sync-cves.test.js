import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { startNvdStub, loadFixture } from './helpers/nvd-stub.js';
import { runOnce, pickScore } from '../jobs/sync-cves.js';
import { createNvdClient } from '../utils/nvd.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

const OPENSSL_CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';

let stub;
let client;
before(async () => {
	stub = await startNvdStub();
	client = createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1, timeoutMs: 500 });
});
after(async () => {
	await stub.close();
	await database.end();
});

beforeEach(async () => {
	await reset();
	stub.reset();
	await database.query(`INSERT INTO software_cpe (vendor, name, version, cpeName, status, lastCheckedAt) VALUES ('openssl', 'openssl', '3.0.0', ?, 'matched', UTC_TIMESTAMP())`, [OPENSSL_CPE]);
});

const linkedCves = async () => {
	const rows = await database.query('SELECT cveID FROM cpe_cve WHERE cpeName = ? ORDER BY cveID', [OPENSSL_CPE]);
	return rows.map(({ cveID }) => cveID);
};

describe('sync-cves runOnce', () => {
	it('stores the CVEs whose vulnerable match covers the CPE', async () => {
		stub.route('/cves/2.0', OPENSSL_CPE, loadFixture('cves-openssl-3.0.0.json'));
		await runOnce({ client });
		assert.deepEqual(await linkedCves(), ['CVE-2021-4044', 'CVE-2022-0778', 'CVE-2022-3996']);

		const [cve] = await database.query('SELECT description, cvssScore, severity, published FROM cve WHERE cveID = ?', ['CVE-2022-0778']);
		assert.equal(Number(cve.cvssScore), 7.5);
		assert.equal(cve.severity, 'HIGH');
		assert.ok(cve.description.length > 0);
		assert.ok(cve.published);
	});

	it('does not link a CVE listing the CPE only as a non-vulnerable platform (Mutt case)', async () => {
		stub.route('/cves/2.0', OPENSSL_CPE, loadFixture('cves-openssl-3.0.0.json'));
		await runOnce({ client });
		const linked = await linkedCves();
		assert.ok(!linked.includes('CVE-2009-1390'));
	});

	it('removes a link NVD no longer reports on re-sync', async () => {
		const fixture = loadFixture('cves-openssl-3.0.0.json');
		stub.route('/cves/2.0', OPENSSL_CPE, fixture);
		await runOnce({ client });

		await database.query('UPDATE software_cpe SET cvesCheckedAt = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 25 HOUR)');
		stub.route('/cves/2.0', OPENSSL_CPE, { ...fixture, vulnerabilities: fixture.vulnerabilities.filter(({ cve }) => cve.id !== 'CVE-2022-0778') });
		await runOnce({ client });
		assert.deepEqual(await linkedCves(), ['CVE-2021-4044', 'CVE-2022-3996']);
	});

	it('skips CPEs synced less than 24 h ago', async () => {
		await database.query('UPDATE software_cpe SET cvesCheckedAt = UTC_TIMESTAMP()');
		await runOnce({ client });
		assert.equal(stub.requests.length, 0);
	});

	it('stores NULL platforms for unconditional links and the criteria for conditional ones', async () => {
		const fixture = loadFixture('cves-openssl-3.0.0.json');
		const conditional = structuredClone(fixture.vulnerabilities.find(({ cve }) => cve.id === 'CVE-2022-3996'));
		conditional.cve.id = 'CVE-2000-0003'; // synthetic: same CVE made Windows-only
		conditional.cve.configurations = [{ operator: 'AND', nodes: [...conditional.cve.configurations[0].nodes, { operator: 'OR', cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*' }] }] }];
		stub.route('/cves/2.0', OPENSSL_CPE, { ...fixture, vulnerabilities: [...fixture.vulnerabilities, conditional] });
		await runOnce({ client });

		const rows = await database.query('SELECT cveID, platforms FROM cpe_cve WHERE cveID IN (?, ?) ORDER BY cveID', ['CVE-2000-0003', 'CVE-2022-3996']);
		assert.deepEqual(rows.map(({ cveID, platforms }) => [cveID, platforms ?? 'NULL']), [['CVE-2000-0003', '["cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"]'], ['CVE-2022-3996', 'NULL']]);
	});

	it('marks the CPE checked even when it has no CVE', async () => {
		await runOnce({ client });
		const [row] = await database.query('SELECT cvesCheckedAt FROM software_cpe');
		assert.ok(row.cvesCheckedAt);
		assert.deepEqual(await linkedCves(), []);
	});
});

describe('sync-cves on a synthetic CPE', () => {
	const CHROME_CPE = 'cpe:2.3:a:google:chrome:122.0.6261.112:*:*:*:*:*:*:*';

	it('queries virtualMatchString and links only the CVEs whose range covers the version', async () => {
		await database.query('DELETE FROM software_cpe');
		await database.query(`INSERT INTO software_cpe (vendor, name, version, cpeName, cpeSynthetic, status, lastCheckedAt) VALUES ('google llc', 'google chrome', '122.0.6261.112', ?, 1, 'matched', UTC_TIMESTAMP())`, [CHROME_CPE]);
		stub.route('/cves/2.0', CHROME_CPE, loadFixture('cves-virtual-chrome-122.0.6261.112.json'));
		await runOnce({ client });

		assert.deepEqual(stub.requests.map(({ query }) => [query.virtualMatchString, query.cpeName]), [[CHROME_CPE, undefined]]);
		const rows = await database.query('SELECT cveID FROM cpe_cve WHERE cpeName = ? ORDER BY cveID', [CHROME_CPE]);
		// CVE-2000-0122 is the fixture's synthetic copy fixed before 122: never linked.
		assert.deepEqual(rows.map(({ cveID }) => cveID), ['CVE-2024-2400', 'CVE-2024-2625', 'CVE-2024-2626']);
	});
});

const metricsOf = id => structuredClone(loadFixture('cves-openssl-3.0.0.json').vulnerabilities.find(({ cve }) => cve.id === id).cve.metrics);

describe('pickScore', () => {
	it('prefers CVSS v3.1', () => {
		const metrics = metricsOf('CVE-2022-0778');
		metrics.cvssMetricV2[0].cvssData.baseScore = 5;
		assert.deepEqual(pickScore(metrics), { cvssScore: 7.5, severity: 'HIGH' });
	});

	it('falls back to v3.0 then v2', () => {
		const metrics = metricsOf('CVE-2022-0778');
		const v31 = metrics.cvssMetricV31;
		delete metrics.cvssMetricV31;
		metrics.cvssMetricV30 = [{ ...v31[0], cvssData: { ...v31[0].cvssData, version: '3.0', baseScore: 7.4 } }];
		assert.equal(pickScore(metrics).cvssScore, 7.4);

		delete metrics.cvssMetricV30;
		assert.deepEqual(pickScore(metrics), { cvssScore: 5, severity: 'MEDIUM' });
	});

	it('returns no score when NVD has no metric', () => {
		assert.deepEqual(pickScore({}), { cvssScore: undefined, severity: undefined });
	});
});
