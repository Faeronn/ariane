import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, createOrganization } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let userA;
beforeEach(async () => {
	await reset();
	await createOrganization('Other', 'other.test');
	userA = await createSignedInUser(server.baseUrl, 'alice');
	const userB = await createSignedInUser(server.baseUrl, 'bob', 'other.test');

	const enrollAndPush = async (user, hostname, software) => {
		const { body } = await api(server.baseUrl, 'POST', '/machines', { token: user.accessToken, body: { hostname } });
		await api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': body.apiKey }, body: { osFamily: 'windows', software } });
		return body.apiKey;
	};
	const shared = { name: 'Acme Tool', version: '1.0' };
	const firstKey = await enrollAndPush(userA, 'a-01', [shared, { name: 'Old Only', version: '0.1' }, { name: 'openssl', vendor: 'openssl', version: '3.0.0' }]);
	await enrollAndPush(userA, 'a-02', [shared, { name: 'Pending Tool', version: '2.0' }]);
	await enrollAndPush(userB, 'b-01', [{ name: 'Secret Tool', version: '9.9' }]);
	// a-01 pushes again without "Old Only": only the latest snapshot counts.
	await api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': firstKey }, body: { osFamily: 'windows', software: [shared, { name: 'openssl', vendor: 'openssl', version: '3.0.0' }] } });

	await database.query('UPDATE software_cpe SET status = ?, lastCheckedAt = UTC_TIMESTAMP() WHERE name = ?', ['unmatched', 'acme tool']);
	await database.query('UPDATE software_cpe SET status = ?, cpeName = ? WHERE name = ?', ['matched', 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*', 'openssl']);
});

describe('GET /software/unmapped', () => {
	it('lists the organization unmapped software, most widespread first', async () => {
		const response = await api(server.baseUrl, 'GET', '/software/unmapped', { token: userA.accessToken });
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.software.map(({ name, status, machineCount }) => `${name}:${status}:${machineCount}`), ['acme tool:unmatched:2', 'pending tool:pending:1']);
		assert.match(response.body.software[0].lastCheckedAt, /Z$/);
	});

	it('never shows another organization software, nor software only in older snapshots', async () => {
		const response = await api(server.baseUrl, 'GET', '/software/unmapped', { token: userA.accessToken });
		const names = new Set(response.body.software.map(({ name }) => name));
		assert.ok(!names.has('secret tool'));
		assert.ok(!names.has('old only'));
	});

	it('requires a token', async () => {
		const response = await api(server.baseUrl, 'GET', '/software/unmapped');
		assert.equal(response.status, 401);
	});
});
