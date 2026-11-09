import { describe, it, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { migrate, MIGRATIONS_DIRECTORY } from '../utils/migrate.js';
import { connect, dropAllTables, rebuildSchema } from './helpers/database.js';

const SCHEMA_TABLES = ['cpe_cve', 'cve', 'domain', 'installed_software', 'inventory_snapshot', 'machines', 'refresh_token', 'software_cpe', 'users', 'verifications'];
const connectMulti = () => connect({ multipleStatements: true });
const run = directory => migrate({ directory, connect: connectMulti });

async function inspect(sql, values) {
	const connection = await connect();
	try {
		return await connection.query(sql, values);
	} finally {
		await connection.end();
	}
}

const names = rows => rows.map(({ name }) => name);
const tables = () => inspect('SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY 1').then(names);
const history = () => inspect('SELECT name FROM schema_migrations ORDER BY name').then(names);

// A directory holding the real initial migration plus extra files.
async function directoryWith(extra = {}) {
	const directory = await mkdtemp(path.join(tmpdir(), 'ariane-migrations-'));
	await copyFile(path.join(MIGRATIONS_DIRECTORY, '001-initial.sql'), path.join(directory, '001-initial.sql'));
	for (const [name, sql] of Object.entries(extra)) await writeFile(path.join(directory, name), sql);
	return directory;
}

beforeEach(dropAllTables);
after(rebuildSchema);

describe('migrate', () => {
	it('builds the whole schema on an empty database and records it', async () => {
		const applied = await run(MIGRATIONS_DIRECTORY);
		assert.ok(applied.includes('001-initial.sql'));
		const created = await tables();
		for (const table of SCHEMA_TABLES) assert.ok(created.includes(table), table);
		const recorded = await history();
		assert.ok(recorded.includes('001-initial.sql'));
	});

	it('applies nothing on a second run', async () => {
		await run(MIGRATIONS_DIRECTORY);
		assert.deepEqual(await run(MIGRATIONS_DIRECTORY), []);
	});

	it('records the initial migration as baseline on a database built from the old dump, keeping rows', async () => {
		const directory = await directoryWith();
		try {
			await run(directory);
			await inspect('DROP TABLE schema_migrations');
			await inspect('INSERT INTO domain (domainName) VALUES (?)', ['kept.test']);

			assert.deepEqual(await run(directory), ['001-initial.sql (baseline)']);
			assert.deepEqual(await history(), ['001-initial.sql']);
			const [domain] = await inspect('SELECT domainName FROM domain');
			assert.equal(domain.domainName, 'kept.test');
		} finally {
			await rm(directory, { recursive: true });
		}
	});

	it('stops at a failing migration without recording it or running the next ones', async () => {
		const directory = await directoryWith({
			'002-broken.sql': 'CREATE TABLE broken (id int;',
			'003-after.sql': 'CREATE TABLE after_broken (id int);'
		});
		try {
			await assert.rejects(run(directory), /Migration 002-broken\.sql failed/);
			assert.deepEqual(await history(), ['001-initial.sql']);
			const remaining = await tables();
			assert.ok(!remaining.includes('after_broken'));
		} finally {
			await rm(directory, { recursive: true });
		}
	});
});
