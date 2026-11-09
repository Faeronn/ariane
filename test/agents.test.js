import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, countRows, captureLogs } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

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

const push = (body, apiKey = machine.apiKey) => api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': apiKey }, body });
const inventory = software => ({ hostname: 'web-01.lan', osFamily: 'linux', osVersion: 'Debian 12', collectedAt: '2026-11-09T10:00:00Z', software });
const THREE_SOFTWARE = [{ name: 'openssl', version: '3.0.0', vendor: 'openssl' }, { name: 'curl', version: '8.4.0' }, { name: 'bash', version: '5.2' }];

describe('POST /agents/inventory', () => {
	it('stores a snapshot with its software and refreshes the machine', async () => {
		const response = await push(inventory(THREE_SOFTWARE));
		assert.equal(response.status, 201);
		assert.equal(typeof response.body.snapshotID, 'number');
		assert.equal(await countRows('installed_software'), 3);

		const [row] = await database.query('SELECT hostname, osFamily, osVersion, lastSeenAt FROM machines WHERE machineID = ?', [machine.machineID]);
		assert.equal(row.hostname, 'web-01.lan');
		assert.equal(row.osFamily, 'linux');
		assert.ok(row.lastSeenAt);
	});

	it('rejects an entry without name with 400 and writes nothing', async () => {
		const response = await push(inventory([{ name: 'curl', version: '8' }, { version: '1.0' }]));
		assert.equal(response.status, 400);
		assert.deepEqual(response.body.errors, ['software[1].name is required']);
		assert.equal(await countRows('inventory_snapshot'), 0);
		assert.equal(await countRows('installed_software'), 0);
	});

	it('rolls back the snapshot when a software row fails to insert', async () => {
		// A temporary CHECK makes the software batch fail after the snapshot insert succeeded.
		await database.query('ALTER TABLE installed_software ADD CONSTRAINT chk_test_version CHECK (version <> \'boom\')');
		const logs = captureLogs();
		try {
			const response = await push(inventory([{ name: 'curl', version: 'boom' }]));
			assert.equal(response.status, 500);
		} finally {
			logs.restore();
			await database.query('ALTER TABLE installed_software DROP CONSTRAINT chk_test_version');
		}
		assert.equal(await countRows('inventory_snapshot'), 0);
	});

	it('rejects more than 10 000 entries with 400 and writes nothing', async () => {
		const software = Array.from({ length: 10_001 }, (_, index) => ({ name: `p${index}` }));
		const response = await push(inventory(software));
		assert.equal(response.status, 400);
		assert.equal(await countRows('inventory_snapshot'), 0);
	});

	it('rejects a body over 5 MB with 413 and writes nothing', async () => {
		const response = await push(inventory(Array.from({ length: 30 }, () => ({ name: 'y'.repeat(200_000) }))));
		assert.equal(response.status, 413);
		assert.equal(await countRows('inventory_snapshot'), 0);
	});

	it('accepts a 3000-entry inventory', async () => {
		const software = Array.from({ length: 3000 }, (_, index) => ({ name: `package-${index}`, vendor: 'debian', version: `1.${index}.0` }));
		const response = await push(inventory(software));
		assert.equal(response.status, 201);
		assert.equal(await countRows('installed_software'), 3000);
	});

	it('rejects a revoked machine key with 401', async () => {
		await api(server.baseUrl, 'DELETE', `/machines/${machine.machineID}`, { token });
		const response = await push(inventory(THREE_SOFTWARE));
		assert.equal(response.status, 401);
	});
});

describe('GET /machines', () => {
	it('lists the machine with lastSeenAt and the software count of its latest snapshot', async () => {
		await push(inventory(THREE_SOFTWARE));
		const response = await api(server.baseUrl, 'GET', '/machines', { token });
		assert.equal(response.status, 200);
		assert.equal(response.body.machines.length, 1);
		const [listed] = response.body.machines;
		assert.equal(listed.machineID, machine.machineID);
		assert.equal(listed.softwareCount, 3);
		assert.match(listed.lastSeenAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
		assert.equal(listed.apiKeyHash, undefined);
	});

	it('requires a user access token', async () => {
		const response = await api(server.baseUrl, 'GET', '/machines');
		assert.equal(response.status, 401);
	});
});

describe('GET /machines/:id', () => {
	it('returns the software of the latest snapshot', async () => {
		await push(inventory(THREE_SOFTWARE));
		const response = await api(server.baseUrl, 'GET', `/machines/${machine.machineID}`, { token });
		assert.equal(response.status, 200);
		assert.equal(response.body.software.length, 3);
		assert.equal(response.body.snapshot.collectedAt, '2026-11-09T10:00:00Z');
	});

	it('shows only the second push after two pushes', async () => {
		await push(inventory(THREE_SOFTWARE));
		await push(inventory([{ name: 'nginx', version: '1.25' }, { name: 'curl', version: '8.5.0' }]));
		const response = await api(server.baseUrl, 'GET', `/machines/${machine.machineID}`, { token });
		assert.deepEqual(response.body.software.map(({ name, version }) => `${name}@${version}`), ['curl@8.5.0', 'nginx@1.25']);
	});

	it('returns an empty software list before any push', async () => {
		const response = await api(server.baseUrl, 'GET', `/machines/${machine.machineID}`, { token });
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.software, []);
		assert.equal(response.body.snapshot, undefined);
	});

	it('answers 404 for an unknown machine and 400 for a non-numeric id', async () => {
		const unknown = await api(server.baseUrl, 'GET', '/machines/999999', { token });
		assert.equal(unknown.status, 404);
		const invalid = await api(server.baseUrl, 'GET', '/machines/abc', { token });
		assert.equal(invalid.status, 400);
	});
});

describe('machine deletion', () => {
	it('cascades to its snapshots and software', async () => {
		await push(inventory(THREE_SOFTWARE));
		await database.query('DELETE FROM machines WHERE machineID = ?', [machine.machineID]);
		assert.equal(await countRows('inventory_snapshot'), 0);
		assert.equal(await countRows('installed_software'), 0);
	});
});
