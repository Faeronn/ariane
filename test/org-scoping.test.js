import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, createOrganization } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let adminA;
let adminB;
let machineA;
let machineB;
beforeEach(async () => {
	await reset();
	await createOrganization('Other', 'other.test');
	adminA = await createSignedInUser(server.baseUrl, 'alice');
	adminB = await createSignedInUser(server.baseUrl, 'bob', 'other.test');
	({ body: machineA } = await api(server.baseUrl, 'POST', '/machines', { token: adminA.accessToken, body: { hostname: 'a-01' } }));
	({ body: machineB } = await api(server.baseUrl, 'POST', '/machines', { token: adminB.accessToken, body: { hostname: 'b-01' } }));
});

const asA = (method, path) => api(server.baseUrl, method, path, { token: adminA.accessToken });

describe('machines scoped to the organization', () => {
	it('lists only the machines of the caller organization', async () => {
		const { body } = await asA('GET', '/machines');
		assert.deepEqual(body.machines.map(({ hostname }) => hostname), ['a-01']);
	});

	it('serves detail and vulnerabilities of an own machine', async () => {
		const detail = await asA('GET', `/machines/${machineA.machineID}`);
		const vulns = await asA('GET', `/machines/${machineA.machineID}/vulns`);
		assert.equal(detail.status, 200);
		assert.equal(vulns.status, 200);
	});

	it('answers 404 for another organization machine on every route and leaves it active', async () => {
		for (const [method, path] of [['GET', ''], ['GET', '/vulns'], ['DELETE', '']]) {
			const response = await asA(method, `/machines/${machineB.machineID}${path}`);
			assert.equal(response.status, 404, `${method} ${path}`);
			assert.deepEqual(response.body, { message: 'Error : Machine not found.' });
		}
		const { body } = await api(server.baseUrl, 'GET', `/machines/${machineB.machineID}`, { token: adminB.accessToken });
		assert.ok(!body.machine.revokedAt);
	});
});
