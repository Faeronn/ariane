import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { api, createUser, verifyUser, createSignedInUser, createOrganization } from './helpers/fixtures.js';
import { reset, connect, dropAllTables, rebuildSchema, TEST_ORG_ID } from './helpers/database.js';
import { startServer } from './helpers/server.js';
import { migrate, MIGRATIONS_DIRECTORY } from '../utils/migrate.js';
import database from '../utils/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

const connectMulti = () => connect({ multipleStatements: true });

async function inspect(sql, values) {
	const connection = await connect();
	try {
		return await connection.query(sql, values);
	} finally {
		await connection.end();
	}
}

const userRow = async userID => {
	const [row] = await database.query('SELECT orgID, role FROM users WHERE userID = ?', [userID]);
	return row;
};

describe('organization membership', () => {
	beforeEach(reset);

	it('makes the first verified user of an organization its admin, the next ones viewers', async () => {
		const first = await createUser(server.baseUrl, 'alice');
		const second = await createUser(server.baseUrl, 'bob');
		await verifyUser(server.baseUrl, second);
		await verifyUser(server.baseUrl, first);

		assert.deepEqual(await userRow(second.userID), { orgID: TEST_ORG_ID, role: 'admin' });
		assert.deepEqual(await userRow(first.userID), { orgID: TEST_ORG_ID, role: 'viewer' });
	});

	it('gives each organization its own first admin', async () => {
		const otherOrg = await createOrganization('Garouda', 'garouda.test');
		await createSignedInUser(server.baseUrl, 'alice');
		const carol = await createSignedInUser(server.baseUrl, 'carol', 'garouda.test');
		assert.deepEqual(await userRow(carol.userID), { orgID: otherOrg, role: 'admin' });
	});

	it('stores the organization on enrolled machines', async () => {
		const { accessToken: token } = await createSignedInUser(server.baseUrl);
		const { body } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname: 'web-01' } });
		const [machine] = await database.query('SELECT orgID FROM machines WHERE machineID = ?', [body.machineID]);
		assert.equal(machine.orgID, TEST_ORG_ID);
	});

	it('refuses a still-valid token of a deleted user', async () => {
		const alice = await createSignedInUser(server.baseUrl);
		await database.query('DELETE FROM users WHERE userID = ?', [alice.userID]);
		const response = await api(server.baseUrl, 'GET', '/machines', { token: alice.accessToken });
		assert.equal(response.status, 401);
	});

	it('refuses a user left without organization', async () => {
		const alice = await createSignedInUser(server.baseUrl);
		await database.query('UPDATE users SET orgID = NULL WHERE userID = ?', [alice.userID]);
		const response = await api(server.baseUrl, 'GET', '/machines', { token: alice.accessToken });
		assert.equal(response.status, 403);
	});
});

describe('organizations migration on existing data', () => {
	let directory;
	before(async () => {
		directory = await mkdtemp(path.join(tmpdir(), 'ariane-orgs-'));
		await copyFile(path.join(MIGRATIONS_DIRECTORY, '001-initial.sql'), path.join(directory, '001-initial.sql'));
		await dropAllTables();
		await migrate({ directory, connect: connectMulti });
		await inspect(`INSERT INTO domain (domainId, domainName) VALUES (1, 'artemis.test'), (2, 'garouda.test'), (3, NULL)`);
		await inspect(`INSERT INTO users (userID, username, role, isVerified) VALUES
			(1, 'a1@artemis.test', NULL, 1), (2, 'a2@artemis.test', 'user', 1), (3, 'a3@artemis.test', NULL, 0),
			(4, 'g1@garouda.test', NULL, 0), (5, 'x1@gone.test', NULL, 1)`);
		await inspect(`INSERT INTO machines (machineID, hostname, apiKeyHash, createdBy, createdAt) VALUES
			(1, 'a-host', REPEAT('a', 64), 2, UTC_TIMESTAMP()), (2, 'orphan-host', REPEAT('b', 64), NULL, UTC_TIMESTAMP())`);
		await copyFile(path.join(MIGRATIONS_DIRECTORY, '002-organizations.sql'), path.join(directory, '002-organizations.sql'));
		await migrate({ directory, connect: connectMulti });
	});
	after(async () => {
		await rm(directory, { recursive: true });
		await rebuildSchema();
	});

	it('creates one organization per named domain and attaches the domains', async () => {
		const rows = await inspect('SELECT o.name, d.domainName FROM organizations o INNER JOIN domain d ON d.orgID = o.orgID ORDER BY o.orgID');
		assert.deepEqual(rows.map(({ name, domainName }) => `${name}:${domainName}`), ['artemis.test:artemis.test', 'garouda.test:garouda.test']);
	});

	it('attaches users by email domain and makes the earliest verified user of each organization admin', async () => {
		const rows = await inspect('SELECT u.userID, o.name, u.role FROM users u LEFT JOIN organizations o ON o.orgID = u.orgID ORDER BY u.userID');
		assert.deepEqual(rows.map(({ userID, name, role }) => `${userID}:${name}:${role}`), [
			'1:artemis.test:admin', '2:artemis.test:viewer', '3:artemis.test:viewer',
			'4:garouda.test:viewer', '5:null:viewer'
		]);
	});

	it('attaches machines to their creator organization, or to the oldest one', async () => {
		const rows = await inspect('SELECT m.hostname, o.name FROM machines m INNER JOIN organizations o ON o.orgID = m.orgID ORDER BY m.machineID');
		assert.deepEqual(rows.map(({ hostname, name }) => `${hostname}:${name}`), ['a-host:artemis.test', 'orphan-host:artemis.test']);
	});
});
