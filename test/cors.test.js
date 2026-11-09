import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, startThrowawayApp } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { createCors } from '../middleware/cors.js';
import { validateConfig } from '../utils/config.js';

const DASHBOARD = 'https://dash.example';
const allowOrigin = response => response.headers.get('access-control-allow-origin') ?? undefined;
const preflight = (baseUrl, path, origin) => api(baseUrl, 'OPTIONS', path, { headers: { Origin: origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' } });

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

describe('CORS on the app (CORS_ORIGINS=https://dash.example in .env.test)', () => {
	it('answers a preflight from a listed origin', async () => {
		const response = await preflight(server.baseUrl, '/machines', DASHBOARD);
		assert.equal(allowOrigin(response), DASHBOARD);
	});

	it('sends no CORS header to another origin', async () => {
		const response = await api(server.baseUrl, 'POST', '/auth/signin', { body: {}, headers: { Origin: 'https://evil.example' } });
		assert.equal(allowOrigin(response), undefined);
	});

	it('never sends CORS headers on agent routes', async () => {
		const response = await api(server.baseUrl, 'POST', '/agents/inventory', { body: {}, headers: { Origin: DASHBOARD } });
		assert.equal(allowOrigin(response), undefined);
	});
});

describe('createCors', () => {
	it('allows no origin when the list is empty', async () => {
		const app = await startThrowawayApp(application => application.get('/ping', createCors([]), (request, response) => response.send({ message: 'ok' })));
		try {
			const response = await api(app.baseUrl, 'GET', '/ping', { headers: { Origin: DASHBOARD } });
			assert.equal(response.status, 200);
			assert.equal(allowOrigin(response), undefined);
		} finally {
			await app.close();
		}
	});

	it('rejects a malformed origin at start-up', () => {
		const { errors } = validateConfig({ CORS_ORIGINS: 'https://ok.example, https://bad.example/path' });
		assert.deepEqual(errors.filter(error => error.startsWith('CORS_ORIGINS')).length, 1);
	});
});
