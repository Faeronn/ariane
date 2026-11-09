import { describe, it, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { reset } from './helpers/database.js';
import { countRows } from './helpers/fixtures.js';
import database from '../utils/database.js';

beforeEach(reset);
after(() => database.end());

describe('database.transaction', () => {
	it('commits the work when it resolves', async () => {
		const result = await database.transaction(async connection => {
			await connection.query('INSERT INTO domain (domainName) VALUES (?)', ['committed.test']);
			return 'done';
		});
		assert.equal(result, 'done');
		assert.equal(await countRows('domain'), 2);
	});

	it('rolls back every statement when the work throws after the first insert', async () => {
		await assert.rejects(database.transaction(async connection => {
			await connection.query('INSERT INTO domain (domainName) VALUES (?)', ['rolled-back.test']);
			await connection.query('INSERT INTO no_such_table VALUES (1)');
		}));
		assert.equal(await countRows('domain'), 1);
	});

	it('releases connections: 10 failing transactions do not exhaust the pool of 5', async () => {
		for (let index = 0; index < 10; index += 1) {
			await assert.rejects(database.transaction(() => Promise.reject(new Error('fail'))));
		}
		const [row] = await database.query('SELECT 1 AS ok');
		assert.equal(row.ok, 1);
	});
});
