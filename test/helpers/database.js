import { readFile } from 'node:fs/promises';
import mariadb from 'mariadb';

export const ALLOWED_DOMAIN = 'ariane.test';

const databaseName = process.env.DB_NAME ?? '';
if (!databaseName.endsWith('_test')) throw new Error(`Refusing to run tests on database "${databaseName}": DB_NAME must end with _test.`);

function connect(options = {}) {
	return mariadb.createConnection({
		host: process.env.DB_HOST,
		port: process.env.DB_PORT,
		user: process.env.DB_USER,
		password: process.env.DB_PASSWORD,
		database: databaseName,
		...options
	});
}

// Run once per `npm test` through --test-global-setup: recreate the schema from the dump.
export async function globalSetup() {
	const schema = await readFile(new URL('../../ariane.sql', import.meta.url), 'utf8');
	const connection = await connect({ multipleStatements: true });
	try {
		await connection.query(schema);
	} finally {
		await connection.end();
	}
}

// Empty every table, then re-seed the allowed signup domain.
export async function reset() {
	const connection = await connect();
	try {
		const tables = await connection.query('SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = \'BASE TABLE\'', [databaseName]);
		await connection.query('SET FOREIGN_KEY_CHECKS = 0');
		for (const { name } of tables) await connection.query(`TRUNCATE TABLE \`${name}\``);
		await connection.query('SET FOREIGN_KEY_CHECKS = 1');
		await connection.query('INSERT INTO domain (domainName) VALUES (?)', [ALLOWED_DOMAIN]);
	} finally {
		await connection.end();
	}
}
