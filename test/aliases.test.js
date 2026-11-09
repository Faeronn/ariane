import { describe, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { MIGRATIONS_DIRECTORY } from '../utils/migrate.js';
import { connect, rebuildSchema } from './helpers/database.js';

after(rebuildSchema);

describe('software aliases migration', () => {
	it('seeds the aliases and sends previously unmatched keys back to pending', async () => {
		const connection = await connect({ multipleStatements: true });
		try {
			await connection.query('DELETE FROM software_cpe');
			await connection.query('DELETE FROM schema_migrations WHERE name = ?', ['003-software-aliases.sql']);
			await connection.query('INSERT INTO software_cpe (vendor, name, version, status) VALUES (?, ?, ?, ?), (?, ?, ?, ?)', ['', 'tool', '1', 'unmatched', '', 'other', '2', 'matched']);
			const sql = await readFile(path.join(MIGRATIONS_DIRECTORY, '003-software-aliases.sql'), 'utf8');
			await connection.query(sql);

			const statuses = await connection.query('SELECT name, status FROM software_cpe ORDER BY name');
			assert.deepEqual(statuses.map(({ name, status }) => `${name}:${status}`), ['other:matched', 'tool:pending']);
			const [{ aliases }] = await connection.query('SELECT COUNT(*) AS aliases FROM software_alias');
			assert.ok(Number(aliases) >= 30);
			const [notepad] = await connection.query('SELECT cpeProduct FROM software_alias WHERE namePattern = ?', ['notepad++%']);
			assert.equal(notepad.cpeProduct, String.raw`notepad\+\+`);
		} finally {
			await connection.end();
		}
	});
});
