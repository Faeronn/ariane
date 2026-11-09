import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import mariadb from 'mariadb';

export const MIGRATIONS_DIRECTORY = path.join(import.meta.dirname, '..', 'migrations');
// A database built from the former ariane.sql dump already holds this migration's tables.
const BASELINE = '001-initial.sql';

function connectFromEnvironment() {
	return mariadb.createConnection({
		host: process.env.DB_HOST,
		port: process.env.DB_PORT,
		user: process.env.DB_USER,
		password: process.env.DB_PASSWORD,
		database: process.env.DB_NAME,
		multipleStatements: true
	});
}

async function tableExists(connection, name) {
	const rows = await connection.query('SELECT 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [name]);
	return rows.length > 0;
}

// Apply every `*.sql` file of `directory` not yet recorded in schema_migrations, in name order.
// Each file is recorded right after it succeeds; the first failure stops the run. MariaDB DDL is
// not transactional, so a failing file may leave its earlier statements applied: keep files small
// and idempotent. Returns the names applied (or recorded as baseline).
export async function migrate({ directory = MIGRATIONS_DIRECTORY, connect = connectFromEnvironment } = {}) {
	const connection = await connect();
	const applied = [];

	try {
		const hasHistory = await tableExists(connection, 'schema_migrations');
		if (!hasHistory) {
			await connection.query('CREATE TABLE schema_migrations (name varchar(255) NOT NULL PRIMARY KEY, appliedAt datetime NOT NULL) ENGINE = InnoDB CHARACTER SET = utf8mb4');
			if (await tableExists(connection, 'users')) {
				await connection.query('INSERT INTO schema_migrations (name, appliedAt) VALUES (?, UTC_TIMESTAMP())', [BASELINE]);
				applied.push(`${BASELINE} (baseline)`);
			}
		}

		const history = await connection.query('SELECT name FROM schema_migrations');
		const recorded = new Set(history.map(({ name }) => name));
		const entries = await readdir(directory);
		const files = entries.filter(name => name.endsWith('.sql')).toSorted();

		for (const name of files.filter(file => !recorded.has(file))) {
			const sql = await readFile(path.join(directory, name), 'utf8');
			try {
				await connection.query(sql);
			} catch (error) {
				throw new Error(`Migration ${name} failed: ${error.message}`, { cause: error });
			}
			await connection.query('INSERT INTO schema_migrations (name, appliedAt) VALUES (?, UTC_TIMESTAMP())', [name]);
			applied.push(name);
		}
	} finally {
		await connection.end();
	}
	return applied;
}
