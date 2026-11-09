import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, countRows } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let admin;
let viewer;
let machine;
beforeEach(async () => {
	await reset();
	admin = await createSignedInUser(server.baseUrl, 'alice');
	viewer = await createSignedInUser(server.baseUrl, 'bob');
	({ body: machine } = await api(server.baseUrl, 'POST', '/machines', { token: admin.accessToken, body: { hostname: 'web-01' } }));
});

describe('roles on machine routes', () => {
	it('lets the admin enroll and revoke', async () => {
		const enrolled = await api(server.baseUrl, 'POST', '/machines', { token: admin.accessToken, body: { hostname: 'web-02' } });
		assert.equal(enrolled.status, 201);
		const revoked = await api(server.baseUrl, 'DELETE', `/machines/${machine.machineID}`, { token: admin.accessToken });
		assert.equal(revoked.status, 200);
	});

	it('lets a viewer read every machine route', async () => {
		for (const path of ['/machines', `/machines/${machine.machineID}`, `/machines/${machine.machineID}/vulns`]) {
			const response = await api(server.baseUrl, 'GET', path, { token: viewer.accessToken });
			assert.equal(response.status, 200, path);
		}
	});

	it('refuses enroll and revoke to a viewer without changing anything', async () => {
		const enrolled = await api(server.baseUrl, 'POST', '/machines', { token: viewer.accessToken, body: { hostname: 'web-02' } });
		assert.equal(enrolled.status, 403);
		assert.deepEqual(enrolled.body, { message: 'Error : Forbidden.' });
		const revoked = await api(server.baseUrl, 'DELETE', `/machines/${machine.machineID}`, { token: viewer.accessToken });
		assert.equal(revoked.status, 403);

		assert.equal(await countRows('machines'), 1);
		const [row] = await database.query('SELECT revokedAt FROM machines');
		assert.ok(!row.revokedAt);
	});
});
