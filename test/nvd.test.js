import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { createNvdClient, NvdError } from '../utils/nvd.js';
import { startNvdStub, loadFixture } from './helpers/nvd-stub.js';

let stub;
before(async () => { stub = await startNvdStub(); });
after(() => stub.close());
beforeEach(() => stub.reset());

const fastClient = options => createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1, timeoutMs: 200, ...options });

describe('NVD client', () => {
	it('returns the products of a CPE search', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		const products = await fastClient().searchCpes('openssl 3.0.0');
		assert.equal(products.length, 3);
		assert.equal(stub.requests[0].query.keywordSearch, 'openssl 3.0.0');
	});

	it('paginates over startIndex until totalResults is reached', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		const products = await fastClient({ pageSize: 2 }).searchCpes('openssl 3.0.0');
		assert.equal(products.length, 3);
		assert.deepEqual(stub.requests.map(request => request.query.startIndex), ['0', '2']);
	});

	it('retries after a 503 then succeeds', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		stub.failNext(503, 2);
		const products = await fastClient().searchCpes('openssl 3.0.0');
		assert.equal(products.length, 3);
		assert.equal(stub.requests.length, 3);
	});

	it('raises an NvdError once retries are exhausted', async () => {
		stub.failNext(403, 5);
		await assert.rejects(fastClient({ retries: 2 }).searchCpes('x'), NvdError);
		assert.equal(stub.requests.length, 3);
	});

	it('does not retry a non-transient error', async () => {
		stub.failNext(404);
		await assert.rejects(fastClient().searchCpes('x'), NvdError);
		assert.equal(stub.requests.length, 1);
	});

	it('turns a timeout into an NvdError', async () => {
		stub.hangNext(5);
		await assert.rejects(fastClient({ retries: 1, timeoutMs: 100 }).searchCpes('x'), NvdError);
	});

	it('sends the apiKey header only when a key is configured', async () => {
		await fastClient().searchCpes('x');
		await fastClient({ apiKey: 'secret-key' }).searchCpes('x');
		assert.equal(stub.requests[0].headers.apikey, undefined);
		assert.equal(stub.requests[1].headers.apikey, 'secret-key');
	});

	it('spaces requests to respect the rate limit window', async () => {
		const client = fastClient({ windowMs: 300, maxRequests: 2 });
		const startedAt = Date.now();
		await Promise.all([client.searchCpes('a'), client.searchCpes('b'), client.searchCpes('c')]);
		assert.ok(Date.now() - startedAt >= 280, 'third request waited for the window');
	});
});
