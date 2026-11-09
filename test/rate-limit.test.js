import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, PASSWORD, createSignedInUser } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';

let server;
before(async () => { server = await startServer(); });
after(() => server.close());
beforeEach(reset);

const signin = username => api(server.baseUrl, 'POST', '/auth/signin', { body: { username, password: PASSWORD } });

// Send `count` requests one after the other and return the statuses.
async function statuses(count, send) {
	const result = [];
	for (let index = 0; index < count; index += 1) {
		const response = await send(index);
		result.push(response.status);
	}
	return result;
}

describe('auth rate limits', () => {
	it('answers normally under the signin limit, then 429 JSON with Retry-After for that account', async () => {
		const answered = await statuses(10, () => signin('bob@ariane.test'));
		assert.ok(answered.every(status => status !== 429));

		const blocked = await signin('bob@ariane.test');
		assert.equal(blocked.status, 429);
		assert.deepEqual(blocked.body, { message: 'Error : Too many requests.' });
		assert.ok(Number(blocked.headers.get('retry-after')) > 0);
		assert.ok(blocked.headers.get('ratelimit'));
	});

	it('keeps answering another account from the same address until the address ceiling', async () => {
		await statuses(11, () => signin('bob@ariane.test'));
		const other = await signin('carol@ariane.test');
		assert.notEqual(other.status, 429);

		const remaining = await statuses(38, index => signin(`user${index}@ariane.test`));
		assert.ok(remaining.every(status => status !== 429));
		const ceiling = await signin('dave@ariane.test');
		assert.equal(ceiling.status, 429);
	});

	const limits = [
		['signup', 5, index => api(server.baseUrl, 'POST', '/auth/signup', { body: { username: `new${index}@ariane.test`, password: PASSWORD } })],
		['verify', 10, () => api(server.baseUrl, 'GET', '/auth/verify?username=bob@ariane.test&code=000000')],
		['refresh', 30, () => api(server.baseUrl, 'POST', '/auth/refresh', { body: { refreshToken: 'unknown' } })]
	];
	for (const [route, limit, send] of limits) {
		it(`stops ${route} after ${limit} requests`, async () => {
			const answered = await statuses(limit, send);
			assert.ok(answered.every(status => status !== 429));
			const blocked = await send(limit);
			assert.equal(blocked.status, 429);
		});
	}
});

describe('agent and global rate limits', () => {
	it('stops a machine after 30 inventories per hour while another machine is still accepted', async () => {
		const { accessToken: token } = await createSignedInUser(server.baseUrl);
		const enroll = hostname => api(server.baseUrl, 'POST', '/machines', { token, body: { hostname } }).then(({ body }) => body.apiKey);
		const [looping, healthy] = [await enroll('loop-01'), await enroll('ok-01')];
		const push = apiKey => api(server.baseUrl, 'POST', '/agents/inventory', { headers: { 'X-Agent-Key': apiKey }, body: { osFamily: 'linux', software: [] } });

		const accepted = await statuses(30, () => push(looping));
		assert.ok(accepted.every(status => status === 201));
		const blocked = await push(looping);
		assert.equal(blocked.status, 429);
		const other = await push(healthy);
		assert.equal(other.status, 201);
	});

	it('answers 429 on any route once an address passes the global ceiling', async () => {
		const answered = await statuses(600, () => api(server.baseUrl, 'GET', '/nowhere'));
		assert.ok(answered.every(status => status === 404));
		const blocked = await api(server.baseUrl, 'GET', '/machines');
		assert.equal(blocked.status, 429);
	});
});
