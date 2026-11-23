import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { createOsvClient, OsvError } from '../utils/osv.js';
import { startOsvStub } from './helpers/osv-stub.js';

let stub;
let client;
before(async () => {
	stub = await startOsvStub();
	client = createOsvClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 500 });
});
after(() => stub.close());
beforeEach(() => stub.reset());

const EXPRESS = { ecosystem: 'npm', name: 'express', version: '4.17.1' };

describe('OSV client', () => {
	it('returns the vulnerability ids of each package, in order (real answers)', async () => {
		const ids = await client.queryBatch([EXPRESS, { ecosystem: 'npm', name: 'left-pad', version: '1.3.0' }, { ecosystem: 'PyPI', name: 'requests', version: '2.25.0' }]);
		assert.deepEqual(ids[0].map(({ id }) => id), ['GHSA-qw6h-vgh9-j6wx', 'GHSA-rv95-896h-c2vc']);
		assert.ok(ids[0].every(({ modified }) => Date.parse(modified) > 0));
		assert.deepEqual(ids[1], []);
		assert.ok(ids[2].some(({ id }) => id === 'PYSEC-2023-74'));
		assert.deepEqual(stub.requests[0].body.queries[0], { package: { ecosystem: 'npm', name: 'express' }, version: '4.17.1' });
	});

	it('splits more than 1000 packages into several batches', async () => {
		const packages = Array.from({ length: 1001 }, (_, index) => ({ ecosystem: 'npm', name: `p${index}`, version: '1.0.0' }));
		const ids = await client.queryBatch(packages);
		assert.equal(ids.length, 1001);
		assert.deepEqual(stub.requests.map(({ body }) => body.queries.length), [1000, 1]);
	});

	it('reads a vulnerability record (real GHSA-rv95-896h-c2vc)', async () => {
		const record = await client.vuln('GHSA-rv95-896h-c2vc');
		assert.deepEqual(record.aliases, ['CVE-2024-29041']);
		assert.equal(record.severity[0].score, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N');
	});

	it('retries after 429 and 503 then succeeds', async () => {
		stub.failNext(429);
		stub.failNext(503);
		const [ids] = await client.queryBatch([EXPRESS]);
		assert.equal(ids.length, 2);
		assert.equal(stub.requests.length, 3);
	});

	it('raises an OsvError once retries are exhausted', async () => {
		stub.failNext(503, 10);
		await assert.rejects(client.queryBatch([EXPRESS]), OsvError);
	});

	it('answers false, without retrying, for a record OSV does not have', async () => {
		assert.equal(await client.vuln('GHSA-none'), false);
		assert.equal(stub.requests.length, 1);
	});

	it('turns a timeout into an OsvError', async () => {
		stub.hangNext(10);
		await assert.rejects(createOsvClient({ baseUrl: stub.baseUrl, backoffMs: 1, timeoutMs: 50, retries: 1 }).queryBatch([EXPRESS]), OsvError);
	});
});
