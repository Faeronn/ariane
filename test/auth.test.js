import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createUser, verifyUser, signIn, createSignedInUser, getVerificationCode, countRows, PASSWORD } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';
import { hashToken } from '../utils/jwt.js';

let server;
before(async () => { server = await startServer(); });
after(async () => { await server.close(); });
beforeEach(reset);

describe('POST /auth/signup', () => {
	it('creates an unverified user and a 6-digit code for an allowed domain', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signup', { body: { username: 'bob@ariane.test', password: PASSWORD, firstname: 'Bob', lastname: 'B' } });
		assert.equal(response.status, 200);
		const [user] = await database.query('SELECT userID, isVerified FROM users WHERE username = ?', ['bob@ariane.test']);
		assert.notEqual(user.isVerified, 1);
		assert.match(await getVerificationCode(user.userID), /^\d{6}$/);
	});

	it('refuses a domain that is not allowed', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signup', { body: { username: 'bob@evil.com', password: PASSWORD, firstname: 'Bob', lastname: 'B' } });
		assert.equal(response.status, 403);
		assert.equal(await countRows('users'), 0);
	});

	it('rejects missing fields', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signup', { body: { username: 'bob@ariane.test' } });
		assert.equal(response.status, 400);
	});

	it('rejects an invalid username', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signup', { body: { username: 'not-an-email', password: PASSWORD, firstname: 'Bob', lastname: 'B' } });
		assert.equal(response.status, 400);
	});
});

describe('POST /auth/signin', () => {
	it('returns tokens for a verified user', async () => {
		const user = await createUser(server.baseUrl);
		await verifyUser(server.baseUrl, user);
		const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: { username: user.username, password: PASSWORD } });
		assert.equal(response.status, 200);
		assert.ok(response.body.accesstoken);
		assert.ok(response.body.refreshToken);
	});

	it('rejects a wrong password with the vague message', async () => {
		const user = await createUser(server.baseUrl);
		await verifyUser(server.baseUrl, user);
		const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: { username: user.username, password: `${PASSWORD}-wrong` } });
		assert.equal(response.status, 401);
		assert.equal(response.body.message, 'Error : Unable to sign in.');
	});

	it('rejects an unverified user with the same vague message', async () => {
		const user = await createUser(server.baseUrl);
		const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: { username: user.username, password: PASSWORD } });
		assert.equal(response.status, 401);
		assert.equal(response.body.message, 'Error : Unable to sign in.');
	});

	it('rejects malformed JSON with 400', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: '{"username":', headers: { 'Content-Type': 'application/json' } });
		assert.equal(response.status, 400);
	});
});

describe('POST /auth/refresh', () => {
	it('rotates the refresh token and rejects the old one', async () => {
		const { refreshToken } = await createSignedInUser(server.baseUrl);
		const first = await api(server.baseUrl, 'POST', '/auth/refresh', { body: { refreshToken } });
		assert.equal(first.status, 200);
		assert.notEqual(first.body.refreshToken, refreshToken);

		const replay = await api(server.baseUrl, 'POST', '/auth/refresh', { body: { refreshToken } });
		assert.equal(replay.status, 401);
	});
});

describe('POST /auth/signout', () => {
	it('deletes the refresh token', async () => {
		const { refreshToken } = await createSignedInUser(server.baseUrl);
		const response = await api(server.baseUrl, 'POST', '/auth/signout', { body: { refreshToken } });
		assert.equal(response.status, 200);
		const rows = await database.query('SELECT id FROM refresh_token WHERE tokenHash = ?', [hashToken(refreshToken)]);
		assert.equal(rows.length, 0);
	});
});

describe('test isolation', () => {
	it('first test creates a user', async () => {
		await createUser(server.baseUrl);
		assert.equal(await countRows('users'), 1);
	});

	it('second test sees an empty users table and the seeded domain', async () => {
		assert.equal(await countRows('users'), 0);
		assert.equal(await countRows('domain'), 1);
	});
});

describe('signIn fixture', () => {
	it('signs in a verified user', async () => {
		const user = await createUser(server.baseUrl, 'carol');
		await verifyUser(server.baseUrl, user);
		const tokens = await signIn(server.baseUrl, user.username);
		assert.ok(tokens.accessToken);
	});
});
