import mariadb from 'mariadb';
import { migrate } from '../../utils/migrate.js';
import { resetRateLimits } from '../../middleware/rate-limit.js';

export const ALLOWED_DOMAIN = 'ariane.test';
export const TEST_ORG_ID = 1;

const databaseName = process.env.DB_NAME ?? '';
if (!databaseName.endsWith('_test')) throw new Error(`Refusing to run tests on database "${databaseName}": DB_NAME must end with _test.`);

export function connect(options = {}) {
	return mariadb.createConnection({
		host: process.env.DB_HOST,
		port: process.env.DB_PORT,
		user: process.env.DB_USER,
		password: process.env.DB_PASSWORD,
		database: databaseName,
		...options
	});
}

const TABLES_SQL = "SELECT TABLE_NAME AS name FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE'";

// Run `statement(name)` on each listed table with foreign key checks off.
async function forEachTable(connection, keep, statement) {
	const tables = await connection.query(TABLES_SQL, [databaseName]);
	await connection.query('SET FOREIGN_KEY_CHECKS = 0');
	for (const { name } of tables.filter(table => keep(table.name))) await connection.query(statement(name));
	await connection.query('SET FOREIGN_KEY_CHECKS = 1');
}

// Drop every table of the test database, including the migration history.
export async function dropAllTables() {
	const connection = await connect();
	try {
		await forEachTable(connection, () => true, name => `DROP TABLE \`${name}\``);
	} finally {
		await connection.end();
	}
}

// Build the schema from scratch through the migrations, the same path as production.
export async function rebuildSchema() {
	await dropAllTables();
	await migrate({ connect: () => connect({ multipleStatements: true }) });
}

// Run once per `npm test` through --test-global-setup.
export async function globalSetup() {
	await rebuildSchema();
}

// Empty every table but the migration history, then re-seed organization 1 owning the allowed domain.
export async function reset() {
	await resetRateLimits();
	const connection = await connect();
	try {
		await forEachTable(connection, name => name !== 'schema_migrations', name => `TRUNCATE TABLE \`${name}\``);
		await connection.query('INSERT INTO organizations (orgID, name, createdAt) VALUES (?, ?, UTC_TIMESTAMP())', [TEST_ORG_ID, 'Test']);
		await connection.query('INSERT INTO domain (domainName, orgID) VALUES (?, ?)', [ALLOWED_DOMAIN, TEST_ORG_ID]);
	} finally {
		await connection.end();
	}
}
