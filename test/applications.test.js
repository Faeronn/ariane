import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { api, createSignedInUser, createOrganization, setRole } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

const LOCKFILE = { filename: 'package-lock.json', content: readFileSync(new URL('fixtures/lockfiles/npm-workspaces-package-lock.json', import.meta.url), 'utf8') };

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let admin;
let viewer;
let applicationID;
// One machine with the gesdoc2 application; express 5.3.0 has an OSV finding, typescript an NVD one.
beforeEach(async () => {
	await reset();
	admin = await createSignedInUser(server.baseUrl);
	viewer = await createSignedInUser(server.baseUrl, 'bob');
	await setRole(viewer.userID, 'viewer');
	const { body: machine } = await api(server.baseUrl, 'POST', '/machines', { token: admin.accessToken, body: { hostname: 'web-01' } });
	const { body } = await api(server.baseUrl, 'POST', '/agents/applications', { headers: { 'X-Agent-Key': machine.apiKey }, body: { name: 'gesdoc2', path: 'C:/dev/gesdoc2', lockfiles: [LOCKFILE] } });
	applicationID = body.applicationID;

	await database.query("INSERT INTO cve (cveID, cvssScore, severity) VALUES ('GHSA-express', 7.5, 'HIGH'), ('CVE-2099-0001', 9.1, 'CRITICAL')");
	await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID) VALUES ('npm', 'express', '5.3.0', 'GHSA-express')");
	await database.query("UPDATE package_vuln_key SET status = 'checked' WHERE name <> 'ajv'");
	const typescript = 'cpe:2.3:a:microsoft:typescript:6.0.3:*:*:*:*:node.js:*:*';
	await database.query("UPDATE software_cpe SET status = 'matched', cpeName = ? WHERE packageName = 'typescript'", [typescript]);
	await database.query("INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, 'CVE-2099-0001')", [typescript]);
});

describe('GET /applications', () => {
	it('lists the organization applications with their package counts, for any member', async () => {
		const { status, body } = await api(server.baseUrl, 'GET', '/applications', { token: viewer.accessToken });
		assert.equal(status, 200);
		assert.equal(body.applications.length, 1);
		const [application] = body.applications;
		assert.deepEqual({ name: application.name, hostname: application.hostname, packages: application.packages, directPackages: application.directPackages }, { name: 'gesdoc2', hostname: 'web-01', packages: 6, directPackages: 3 });
	});

	it('shows nothing of another organization', async () => {
		await createOrganization('Other', 'other.test');
		const carol = await createSignedInUser(server.baseUrl, 'carol', 'other.test');
		const list = await api(server.baseUrl, 'GET', '/applications', { token: carol.accessToken });
		assert.deepEqual(list.body.applications, []);
		const detail = await api(server.baseUrl, 'GET', `/applications/${applicationID}`, { token: carol.accessToken });
		assert.equal(detail.status, 404);
		assert.equal(detail.body.message, 'Error : Application not found.');
	});

	it('requires a token and a numeric id', async () => {
		const anonymous = await api(server.baseUrl, 'GET', '/applications');
		const badId = await api(server.baseUrl, 'GET', '/applications/abc', { token: admin.accessToken });
		assert.equal(anonymous.status, 401);
		assert.equal(badId.status, 400);
	});
});

describe('GET /applications/:id', () => {
	it('returns the packages of the latest snapshot', async () => {
		const { body } = await api(server.baseUrl, 'GET', `/applications/${applicationID}`, { token: admin.accessToken });
		assert.equal(body.application.name, 'gesdoc2');
		assert.deepEqual(body.packages.find(({ name }) => name === 'typescript'), { ecosystem: 'npm', name: 'typescript', version: '6.0.3', direct: true, dev: true });
		assert.equal(body.packages.length, 6);
	});
});

describe('GET /applications/:id/vulns', () => {
	it('lists the findings of both sources, highest score first, with flags and pending scans', async () => {
		const { body } = await api(server.baseUrl, 'GET', `/applications/${applicationID}/vulns`, { token: viewer.accessToken });
		assert.deepEqual(body.vulnerabilities.map(({ cveID, sources, direct, dev }) => `${cveID}:${sources.join('+')}:${direct ? 'direct' : 'transitive'}:${dev ? 'dev' : 'runtime'}`), [
			'CVE-2099-0001:nvd:direct:dev',
			'GHSA-express:osv:direct:runtime'
		]);
		assert.equal(body.unscanned, 2); // both ajv versions still wait for OSV
	});
});

describe('GET /fleet/summary with applications', () => {
	it('counts applications and their vulnerabilities', async () => {
		const { body } = await api(server.baseUrl, 'GET', '/fleet/summary', { token: admin.accessToken });
		assert.deepEqual(body.applications, { total: 1 });
		assert.equal(body.vulnerabilities.total, 2);
		assert.equal(body.vulnerabilities.affectedMachines, 1);
	});
});
