import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, captureLogs, startThrowawayApp } from './helpers/fixtures.js';
import authenticateAgent from '../middleware/authenticate-agent.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';
import logger from '../utils/logger.js';

let server;
let agentApp;
before(async () => {
	server = await startServer();
	// The real agent route arrives with inventory ingestion; this one only exercises the middleware.
	agentApp = await startThrowawayApp(app => app.get('/agent-only', authenticateAgent, (request, response) => response.send({ message: 'ok', machineID: request.machine.machineID })));
});
after(async () => {
	await agentApp.close();
	await server.close();
});

let token;
beforeEach(async () => {
	await reset();
	({ accessToken: token } = await createSignedInUser(server.baseUrl));
});

const enroll = (hostname = 'web-01') => api(server.baseUrl, 'POST', '/machines', { token, body: { hostname } });
const callAsAgent = apiKey => api(agentApp.baseUrl, 'GET', '/agent-only', { headers: apiKey === undefined ? {} : { 'X-Agent-Key': apiKey } });

describe('POST /machines', () => {
	it('enrolls a machine and returns its id and plain key once', async () => {
		const response = await enroll();
		assert.equal(response.status, 201);
		assert.equal(typeof response.body.machineID, 'number');
		assert.ok(response.body.apiKey.length >= 43);
	});

	it('stores only a 64-char hash of the key', async () => {
		const { body } = await enroll();
		const [machine] = await database.query('SELECT * FROM machines WHERE machineID = ?', [body.machineID]);
		assert.match(machine.apiKeyHash, /^[\da-f]{64}$/);
		assert.ok(!Object.values(machine).includes(body.apiKey));
	});

	it('requires a user access token', async () => {
		const response = await api(server.baseUrl, 'POST', '/machines', { body: { hostname: 'web-01' } });
		assert.equal(response.status, 401);
	});

	it('rejects an invalid hostname', async () => {
		const response = await enroll('bad host/name');
		assert.equal(response.status, 400);
	});
});

describe('DELETE /machines/:id', () => {
	it('revokes the machine', async () => {
		const { body } = await enroll();
		const response = await api(server.baseUrl, 'DELETE', `/machines/${body.machineID}`, { token });
		assert.equal(response.status, 200);
		const [machine] = await database.query('SELECT revokedAt FROM machines WHERE machineID = ?', [body.machineID]);
		assert.ok(machine.revokedAt);
	});

	it('answers 404 for an unknown machine and 400 for a non-numeric id', async () => {
		const unknown = await api(server.baseUrl, 'DELETE', '/machines/999999', { token });
		assert.equal(unknown.status, 404);
		const invalid = await api(server.baseUrl, 'DELETE', '/machines/abc', { token });
		assert.equal(invalid.status, 400);
	});
});

describe('authenticateAgent middleware', () => {
	it('accepts the key of an enrolled machine', async () => {
		const { body } = await enroll();
		const response = await callAsAgent(body.apiKey);
		assert.equal(response.status, 200);
		assert.equal(response.body.machineID, body.machineID);
	});

	it('rejects a missing or wrong key with 401', async () => {
		const missing = await callAsAgent();
		assert.equal(missing.status, 401);
		const wrong = await callAsAgent('not-a-real-key');
		assert.equal(wrong.status, 401);
	});

	it('rejects the key of a revoked machine with 401', async () => {
		const { body } = await enroll();
		await api(server.baseUrl, 'DELETE', `/machines/${body.machineID}`, { token });
		const response = await callAsAgent(body.apiKey);
		assert.equal(response.status, 401);
		assert.equal(response.body.message, 'Error : Invalid agent key.');
	});

	it('redacts the agent key header from logs', () => {
		const logs = captureLogs();
		try {
			logger.error({ req: { headers: { 'x-agent-key': 'leaked-secret', host: 'h' } } }, 'probe');
		} finally {
			logs.restore();
		}
		assert.equal(logs.lines.length, 1);
		assert.doesNotMatch(JSON.stringify(logs.lines[0]), /leaked-secret/);
	});
});
