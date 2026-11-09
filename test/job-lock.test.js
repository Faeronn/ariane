import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { withJobLock } from '../utils/job-lock.js';
import { runOnce } from '../jobs/sync-cves.js';
import { createNvdClient } from '../utils/nvd.js';
import { startNvdStub } from './helpers/nvd-stub.js';
import { connect, reset } from './helpers/database.js';
import database from '../utils/database.js';

const lockName = name => `${process.env.DB_NAME}:${name}`;

// Another "instance": a separate connection holding the job's lock.
async function holdLock(name) {
	const connection = await connect();
	await connection.query('SELECT GET_LOCK(?, 0)', [lockName(name)]);
	return { release: () => connection.end() };
}

async function isFree(name) {
	const connection = await connect();
	try {
		const [{ free }] = await connection.query('SELECT IS_FREE_LOCK(?) AS free', [lockName(name)]);
		return Number(free) === 1;
	} finally {
		await connection.end();
	}
}

let stub;
before(async () => {
	await reset();
	stub = await startNvdStub();
	await database.query(`INSERT INTO software_cpe (vendor, name, version, cpeName, status) VALUES ('openssl', 'openssl', '3.0.0', 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*', 'matched')`);
});
after(async () => {
	await stub.close();
	await database.end();
});

describe('withJobLock', () => {
	it('runs the work when the lock is free and releases it afterwards', async () => {
		const result = await withJobLock('demo', async () => {
			assert.equal(await isFree('demo'), false);
			return 'ran';
		});
		assert.equal(result, 'ran');
		assert.equal(await isFree('demo'), true);
	});

	it('skips the tick while another connection holds the lock', async () => {
		const other = await holdLock('sync-cves');
		try {
			const client = createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1 });
			assert.deepEqual(await runOnce({ client }), { skipped: true });
			assert.equal(stub.requests.length, 0);
		} finally {
			await other.release();
		}
	});

	it('releases the lock and the connection when the work throws', async () => {
		for (let index = 0; index < 8; index += 1) {
			await assert.rejects(withJobLock('demo', () => Promise.reject(new Error('boom'))), /boom/);
		}
		assert.equal(await isFree('demo'), true);
		const [row] = await database.query('SELECT 1 AS ok');
		assert.equal(row.ok, 1);
	});
});
