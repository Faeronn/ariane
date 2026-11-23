import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { createPackagistClient, PackagistError } from '../utils/packagist.js';
import { startPackagistStub } from './helpers/packagist-stub.js';

let stub;
let client;
before(async () => {
	stub = await startPackagistStub();
	client = createPackagistClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 500 });
});
after(() => stub.close());
beforeEach(() => stub.reset());

describe('Packagist client', () => {
	it('returns the advisories of each requested package (real symfony/mime answer)', async () => {
		const advisories = await client.advisories(['symfony/mime', 'acme/none']);
		assert.deepEqual(Object.keys(advisories), ['symfony/mime']);
		assert.ok(advisories['symfony/mime'].some(({ cve }) => cve === 'CVE-2026-45070'));
		assert.deepEqual(stub.requests[0].names, ['symfony/mime', 'acme/none']);
	});

	it('asks for at most 100 packages per request, each name once', async () => {
		const names = Array.from({ length: 150 }, (_, index) => `acme/p${index}`);
		await client.advisories([...names, 'acme/p0']);
		assert.deepEqual(stub.requests.map(({ names: sent }) => sent.length), [100, 50]);
	});

	it('retries after 429 and 503, then raises a PackagistError when it keeps failing', async () => {
		stub.failNext(429);
		stub.failNext(503);
		const advisories = await client.advisories(['symfony/mime']);
		assert.ok(advisories['symfony/mime']);
		stub.failNext(503, 10);
		await assert.rejects(client.advisories(['symfony/mime']), PackagistError);
	});

	it('turns a timeout into a PackagistError', async () => {
		stub.hangNext(10);
		await assert.rejects(createPackagistClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 50, retries: 1 }).advisories(['symfony/mime']), PackagistError);
	});
});
