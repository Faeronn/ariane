import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { api, createSignedInUser, countRows } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

const fixture = name => readFileSync(new URL(`fixtures/lockfiles/${name}`, import.meta.url), 'utf8');
const NPM = { filename: 'package-lock.json', content: fixture('npm-workspaces-package-lock.json') };

let server;
before(async () => { server = await startServer(); });
after(async () => { await server.close(); });

let token;
let machine;
beforeEach(async () => {
	await reset();
	({ accessToken: token } = await createSignedInUser(server.baseUrl));
	({ body: machine } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname: 'web-01' } }));
});

const send = (body, apiKey = machine.apiKey) => api(server.baseUrl, 'POST', '/agents/applications', { headers: { 'X-Agent-Key': apiKey }, body });
const dependencies = snapshotID => database.query('SELECT ecosystem, name, version, direct, dev FROM application_dependency WHERE snapshotID = ? ORDER BY ecosystem, name, version', [snapshotID])
	.then(rows => rows.map(({ ecosystem, name, version, direct, dev }) => `${ecosystem}:${name}@${version}${direct ? ' direct' : ''}${dev ? ' dev' : ''}`));
const lockfileOf = packages => ({ filename: 'package-lock.json', content: JSON.stringify({ lockfileVersion: 3, packages }) });

describe('POST /agents/applications', () => {
	it('stores the application with a snapshot of its packages, keys pending for OSV', async () => {
		const response = await send({ name: 'gesdoc2', path: String.raw`C:\dev\gesdoc2`, lockfiles: [NPM] });
		assert.equal(response.status, 201);
		assert.equal(response.body.message, 'Application received.');
		assert.equal(response.body.packages, 6);
		const rows = await dependencies(response.body.snapshotID);
		assert.ok(rows.includes('npm:express@5.3.0 direct'));
		const [application] = await database.query('SELECT machineID, orgID, name, path FROM applications WHERE applicationID = ?', [response.body.applicationID]);
		assert.deepEqual({ ...application }, { machineID: machine.machineID, orgID: 1, name: 'gesdoc2', path: String.raw`C:\dev\gesdoc2` });
		const [{ pending }] = await database.query("SELECT COUNT(*) AS pending FROM package_vuln_key WHERE status = 'pending'");
		assert.equal(Number(pending), 6);
	});

	it('updates the same application in place with a new snapshot', async () => {
		const first = await send({ name: 'gesdoc2', lockfiles: [NPM] });
		const second = await send({ name: 'gesdoc2', lockfiles: [lockfileOf({ '': { dependencies: { ms: '2.1.3' } }, 'node_modules/ms': { version: '2.1.3' } })] });
		assert.equal(second.body.applicationID, first.body.applicationID);
		assert.notEqual(second.body.snapshotID, first.body.snapshotID);
		assert.deepEqual(await dependencies(second.body.snapshotID), ['npm:ms@2.1.3 direct']);
		assert.equal(await countRows('applications'), 1);
	});

	it('reads composer.lock with its composer.json and uv.lock, sent with their paths', async () => {
		const response = await send({ name: 'mixed', lockfiles: [
			{ filename: String.raw`C:\dev\argdoc\composer.lock`, content: fixture('composer.lock') },
			{ filename: 'argdoc/composer.json', content: fixture('composer.json') },
			{ filename: 'uv.lock', content: fixture('uv.lock') }
		] });
		assert.equal(response.status, 201);
		const rows = await dependencies(response.body.snapshotID);
		assert.ok(rows.includes('Packagist:doctrine/orm@3.7.5 direct'));
		assert.ok(rows.includes('PyPI:httpx@0.28.1 direct'));
		assert.equal(response.body.packages, 6 + 16);
	});

	it('refuses bad payloads with 400, naming each problem, and writes nothing', async () => {
		const cases = [
			[{ lockfiles: [NPM] }, 'name is required'],
			[{ name: 'x', lockfiles: [] }, 'lockfiles must be a non-empty array'],
			[{ name: 'x', lockfiles: [{ filename: 'yarn.lock', content: '' }] }, 'lockfiles[0].filename must be one of package-lock.json, composer.lock, uv.lock, composer.json'],
			[{ name: 'x', lockfiles: [{ filename: 'composer.json', content: '{}' }] }, 'lockfiles must hold one of package-lock.json, composer.lock, uv.lock'],
			[{ name: 'x', lockfiles: [{ filename: 'package-lock.json', content: '{' }] }, /^package-lock\.json: unreadable/]
		];
		for (const [body, error] of cases) {
			const response = await send(body);
			assert.equal(response.status, 400);
			assert.equal(response.body.message, 'Error : Invalid application.');
			assert.ok(response.body.errors.some(message => (error instanceof RegExp ? error.test(message) : message === error)), JSON.stringify(response.body.errors));
		}
		assert.equal(await countRows('applications'), 0);
	});

	it('refuses more than 20 000 packages with 400', async () => {
		const packages = Object.fromEntries(Array.from({ length: 20_001 }, (_, index) => [`node_modules/p${index}`, { version: '1.0.0' }]));
		const response = await send({ name: 'huge', lockfiles: [lockfileOf(packages)] });
		assert.equal(response.status, 400);
		assert.deepEqual(response.body.errors, ['lockfiles hold more than 20000 packages']);
	});

	it('refuses a body over 5 MB with 413', async () => {
		const response = await send({ name: 'big', lockfiles: [{ filename: 'package-lock.json', content: 'x'.repeat(6 * 1024 * 1024) }] });
		assert.equal(response.status, 413);
	});

	it('refuses a revoked machine key with 401', async () => {
		await api(server.baseUrl, 'DELETE', `/machines/${machine.machineID}`, { token });
		const response = await send({ name: 'gesdoc2', lockfiles: [NPM] });
		assert.equal(response.status, 401);
	});
});
