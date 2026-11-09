import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, createOrganization } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let admin;
let viewer;
let outsider;
beforeEach(async () => {
	await reset();
	await createOrganization('Other', 'other.test');
	admin = await createSignedInUser(server.baseUrl, 'alice');
	viewer = await createSignedInUser(server.baseUrl, 'bob');
	outsider = await createSignedInUser(server.baseUrl, 'xavier', 'other.test');
});

const setRole = (actor, userID, role) => api(server.baseUrl, 'PATCH', `/users/${userID}/role`, { token: actor.accessToken, body: { role } });

describe('GET /users', () => {
	it('lists the members of the caller organization without secrets', async () => {
		const response = await api(server.baseUrl, 'GET', '/users', { token: viewer.accessToken });
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.users.map(({ username, role, isVerified }) => `${username}:${role}:${isVerified}`), ['alice@ariane.test:admin:true', 'bob@ariane.test:viewer:true']);
		assert.doesNotMatch(response.text, /password|\$2[aby]\$/);
	});
});

describe('PATCH /users/:id/role', () => {
	it('promotes a viewer, who can then enroll machines', async () => {
		const response = await setRole(admin, viewer.userID, 'admin');
		assert.equal(response.status, 200);
		const enrolled = await api(server.baseUrl, 'POST', '/machines', { token: viewer.accessToken, body: { hostname: 'web-01' } });
		assert.equal(enrolled.status, 201);
	});

	it('refuses to demote the last admin', async () => {
		const response = await setRole(admin, admin.userID, 'viewer');
		assert.equal(response.status, 409);
		assert.deepEqual(response.body, { message: 'Error : Last admin.' });
		const listed = await api(server.baseUrl, 'GET', '/users', { token: admin.accessToken });
		assert.equal(listed.body.users[0].role, 'admin');
	});

	it('allows demoting an admin when another admin remains', async () => {
		await setRole(admin, viewer.userID, 'admin');
		const response = await setRole(admin, admin.userID, 'viewer');
		assert.equal(response.status, 200);
	});

	it('answers 404 for a user of another organization', async () => {
		const response = await setRole(admin, outsider.userID, 'viewer');
		assert.equal(response.status, 404);
	});

	it('refuses role changes to viewers and invalid roles', async () => {
		const byViewer = await setRole(viewer, admin.userID, 'viewer');
		assert.equal(byViewer.status, 403);
		const invalid = await setRole(admin, viewer.userID, 'superadmin');
		assert.equal(invalid.status, 400);
	});
});
