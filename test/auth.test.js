import { describe, it, before, beforeEach, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { api, createUser, verifyUser, signIn, createSignedInUser, getVerificationCode, countRows, captureLogs, startThrowawayApp, PASSWORD } from './helpers/fixtures.js';
import authenticateUser from '../middleware/authenticate-user.js';
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

describe('POST /auth/logout', () => {
	it('deletes the refresh token', async () => {
		const { refreshToken } = await createSignedInUser(server.baseUrl);
		const response = await api(server.baseUrl, 'POST', '/auth/logout', { body: { refreshToken } });
		assert.equal(response.status, 200);
		const rows = await database.query('SELECT id FROM refresh_token WHERE tokenHash = ?', [hashToken(refreshToken)]);
		assert.equal(rows.length, 0);
	});

	it('the old /auth/signout route is gone', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signout', { body: { refreshToken: 'x' } });
		assert.equal(response.status, 404);
	});
});

const verify = (username, code) => api(server.baseUrl, 'GET', `/auth/verify?username=${encodeURIComponent(username)}&code=${code}`);
const wrongCode = code => String((Number(code) + 1) % 1_000_000).padStart(6, '0');
const statusOf = async request => {
	const response = await request;
	return response.status;
};
async function isVerified(userID) {
	const [user] = await database.query('SELECT isVerified FROM users WHERE userID = ?', [userID]);
	return user.isVerified === 1;
}

describe('GET /auth/verify', () => {

	it('verifies the user owning the code', async () => {
		const user = await createUser(server.baseUrl);
		const response = await verify(user.username, await getVerificationCode(user.userID));
		assert.equal(response.status, 200);
		assert.ok(await isVerified(user.userID));
		assert.equal(await countRows('verifications'), 0);
	});

	it('rejects the code of another user', async () => {
		const alice = await createUser(server.baseUrl, 'alice');
		const bob = await createUser(server.baseUrl, 'bob');
		const aliceCode = await getVerificationCode(alice.userID);
		const bobCode = await getVerificationCode(bob.userID);
		if (aliceCode === bobCode) await database.query('UPDATE verifications SET verificationCode = ? WHERE userID = ?', [wrongCode(aliceCode), bob.userID]);

		const response = await verify(alice.username, await getVerificationCode(bob.userID));
		assert.equal(response.status, 400);
		assert.ok(!(await isVerified(alice.userID)));
	});

	it('locks the code after 5 wrong attempts, even for the right code', async () => {
		const user = await createUser(server.baseUrl);
		const code = await getVerificationCode(user.userID);
		for (let attempt = 0; attempt < 5; attempt += 1) assert.equal(await statusOf(verify(user.username, wrongCode(code))), 400);

		const response = await verify(user.username, code);
		assert.equal(response.status, 410);
		assert.equal(await countRows('verifications'), 0);
		assert.ok(!(await isVerified(user.userID)));
	});

	it('rejects an expired code with 410', async () => {
		const user = await createUser(server.baseUrl);
		await database.query('UPDATE verifications SET expiryDate = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE) WHERE userID = ?', [user.userID]);
		const response = await verify(user.username, await getVerificationCode(user.userID));
		assert.equal(response.status, 410);
		assert.ok(!(await isVerified(user.userID)));
	});

	it('answers an unknown user like a wrong code', async () => {
		const response = await verify('nobody@ariane.test', '123456');
		assert.equal(response.status, 400);
		assert.equal(response.body.message, 'Error : Invalid verification code.');
	});

	it('rejects missing or malformed parameters', async () => {
		assert.equal(await statusOf(api(server.baseUrl, 'GET', '/auth/verify?code=123456')), 400);
		assert.equal(await statusOf(verify('alice@ariane.test', '12ab56')), 400);
	});

	it('the old POST /auth/verify/:code route is gone', async () => {
		assert.equal(await statusOf(api(server.baseUrl, 'POST', '/auth/verify/123456')), 404);
	});
});

describe('authenticateUser middleware', () => {
	let protectedServer;
	before(async () => {
		protectedServer = await startThrowawayApp(app => app.get('/private', authenticateUser, (request, response) => response.send({ message: 'ok', user: request.user.username })));
	});
	after(() => protectedServer.close());
	const privateUrl = () => protectedServer.baseUrl;

	it('accepts a valid access token', async () => {
		const { accessToken, username } = await createSignedInUser(server.baseUrl);
		const response = await api(privateUrl(), 'GET', '/private', { token: accessToken });
		assert.equal(response.status, 200);
		assert.equal(response.body.user, username);
	});

	it('rejects a missing Bearer with 401', async () => {
		assert.equal(await statusOf(api(privateUrl(), 'GET', '/private')), 401);
	});

	it('rejects an invalid token with 403', async () => {
		assert.equal(await statusOf(api(privateUrl(), 'GET', '/private', { token: 'not.a.jwt' })), 403);
	});
});

describe('unhandled database failure', () => {
	it('signin answers 500 JSON and logs the error with pino', async () => {
		const logs = captureLogs();
		const queryMock = mock.method(database, 'query', () => Promise.reject(new Error('database is down')));
		try {
			const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: { username: 'alice@ariane.test', password: PASSWORD } });
			assert.equal(response.status, 500);
			assert.equal(response.body.message, 'Error : Unable to sign in.');
		} finally {
			queryMock.mock.restore();
			logs.restore();
		}
		assert.ok(logs.lines.some(line => line.level === 50 && line.err?.message === 'database is down'));
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
