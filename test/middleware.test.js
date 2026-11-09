import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import errorHandler from '../middleware/error-handler.js';
import jsonBody from '../middleware/json-body.js';
import { api, captureLogs, startThrowawayApp } from './helpers/fixtures.js';
import database from '../utils/database.js';

let server;
let baseUrl;
before(async () => {
	server = await startThrowawayApp(app => {
		app.use(jsonBody);
		app.post('/echo', (request, response) => response.send({ message: 'ok', body: request.body }));
		app.get('/boom', () => { throw new Error('secret internal detail'); });
		app.get('/boom-async', async () => { throw new Error('secret async detail'); });
		app.use(errorHandler);
	});
	baseUrl = server.baseUrl;
});
after(async () => {
	await server.close();
	await database.end(); // opened by the fixtures import
});

describe('jsonBody middleware', () => {
	it('parses valid JSON', async () => {
		const response = await api(baseUrl, 'POST', '/echo', { body: { a: 1 } });
		assert.equal(response.status, 200);
		assert.deepEqual(response.body.body, { a: 1 });
	});

	it('answers 400 JSON on malformed JSON', async () => {
		const response = await api(baseUrl, 'POST', '/echo', { body: '{"a":', headers: { 'Content-Type': 'application/json' } });
		assert.equal(response.status, 400);
		assert.equal(response.body.message, 'Error : Bad JSON formatting.');
	});
});

describe('errorHandler middleware', () => {
	for (const path of ['/boom', '/boom-async']) {
		it(`answers 500 JSON without the error details for ${path}`, async () => {
			const logs = captureLogs();
			let response;
			try {
				response = await api(baseUrl, 'GET', path);
			} finally {
				logs.restore();
			}
			assert.equal(response.status, 500);
			assert.deepEqual(response.body, { message: 'Error : Internal server error.' });
			assert.doesNotMatch(response.text, /secret|at /);
			assert.ok(logs.lines.some(line => line.level === 50 && /secret/.test(line.err?.message)));
		});
	}
});
