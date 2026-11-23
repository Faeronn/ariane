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

const entry = (vulnerabilities, cveID) => vulnerabilities.find(vulnerability => vulnerability.cveID === cveID);

describe('machineVulnerabilities with application dependencies', () => {
	const EXPRESS_CPE = 'cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:node.js:*:*';

	// App "shop" on the machine: express 4.17.1 (direct) and qs 6.7.0 (transitive), snapshot 2 is
	// the latest; snapshot 1 held lodash, which must not count any more.
	beforeEach(async () => {
		await database.query("INSERT INTO applications (applicationID, orgID, machineID, name, createdAt, lastSeenAt) VALUES (1, 1, ?, 'shop', UTC_TIMESTAMP(), UTC_TIMESTAMP())", [machineID]);
		await database.query('INSERT INTO application_snapshot (snapshotID, applicationID, receivedAt) VALUES (1, 1, UTC_TIMESTAMP()), (2, 1, UTC_TIMESTAMP())');
		await database.query("INSERT INTO application_dependency (snapshotID, ecosystem, name, version, direct, dev) VALUES (1, 'npm', 'lodash', '4.17.20', 1, 0), (2, 'npm', 'express', '4.17.1', 1, 0), (2, 'npm', 'qs', '6.7.0', 0, 0)");
		await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status, ecosystem, packageName) VALUES ('', 'express', '4.17.1', ?, 'matched', 'npm', 'express')", [EXPRESS_CPE]);
		for (const [cveID, score] of [['CVE-2024-29041', 6.1], ['GHSA-only-osv', 7.5], ['CVE-2024-0001', 4], ['CVE-2021-0001', 9]]) {
			await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, ?, ?)', [cveID, score, 'HIGH']);
		}
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?), (?, ?)', [EXPRESS_CPE, 'CVE-2024-29041', EXPRESS_CPE, 'CVE-2024-0001']);
		await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID) VALUES ('npm', 'express', '4.17.1', 'CVE-2024-29041'), ('npm', 'qs', '6.7.0', 'GHSA-only-osv'), ('npm', 'lodash', '4.17.20', 'CVE-2021-0001')");
	});

	it('lists a vulnerability reached by both sources once, with both', async () => {
		const vulnerabilities = await machineVulnerabilities(machineID);
		const express = entry(vulnerabilities, 'CVE-2024-29041');
		assert.deepEqual(express.sources, ['nvd', 'osv']);
		assert.deepEqual(express.software, [{ name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'shop' }]);
		assert.equal(express.versionNormalized, false);
	});

	it('says which single source found the others, programs included', async () => {
		const vulnerabilities = await machineVulnerabilities(machineID);
		assert.deepEqual(entry(vulnerabilities, 'GHSA-only-osv').sources, ['osv']);
		assert.deepEqual(entry(vulnerabilities, 'CVE-2024-0001').sources, ['nvd']);
		assert.deepEqual(entry(vulnerabilities, 'CVE-2000-0002').sources, ['nvd']);
	});

	it('never lends a package finding to a program of the same name and version', async () => {
		await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status, ecosystem) VALUES ('', 'express', '4.17.1', ?, 'matched', '')", ['cpe:2.3:a:other:express:4.17.1:*:*:*:*:*:*:*']);
		await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) SELECT MAX(snapshotID), '', 'express', '4.17.1' FROM inventory_snapshot WHERE machineID = ?", [machineID]);
		const vulnerabilities = await machineVulnerabilities(machineID);
		const express = entry(vulnerabilities, 'CVE-2024-0001');
		assert.deepEqual(express.software, [{ name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'shop' }]);
	});

	it('names Packagist as a source next to OSV for a Composer finding', async () => {
		await database.query("INSERT INTO application_dependency (snapshotID, ecosystem, name, version, direct, dev) VALUES (2, 'Packagist', 'symfony/mime', '7.4.19', 1, 0)");
		await database.query("INSERT INTO cve (cveID, severity, source) VALUES ('CVE-2026-45070', 'MEDIUM', 'packagist'), ('PKSA-wtxr-p26d-nn42', 'HIGH', 'packagist')");
		await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID, source) VALUES ('Packagist', 'symfony/mime', '7.4.19', 'CVE-2026-45070', 'osv'), ('Packagist', 'symfony/mime', '7.4.19', 'CVE-2026-45070', 'packagist'), ('Packagist', 'symfony/mime', '7.4.19', 'PKSA-wtxr-p26d-nn42', 'packagist')");
		const vulnerabilities = await machineVulnerabilities(machineID);
		assert.deepEqual(entry(vulnerabilities, 'CVE-2026-45070').sources, ['osv', 'packagist']);
		assert.deepEqual(entry(vulnerabilities, 'PKSA-wtxr-p26d-nn42').sources, ['packagist']);
		assert.equal(entry(vulnerabilities, 'CVE-2026-45070').software.length, 1);
	});

	it('reads only the latest snapshot of each application', async () => {
		const vulnerabilities = await machineVulnerabilities(machineID);
		assert.equal(entry(vulnerabilities, 'CVE-2021-0001'), undefined);
		assert.deepEqual(vulnerabilities.map(({ cveID }) => cveID), ['CVE-2000-0002', 'GHSA-only-osv', 'CVE-2024-29041', 'CVE-2000-0001', 'CVE-2024-0001']);
	});
});
