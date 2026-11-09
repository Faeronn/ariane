import database from './database.js';

// Run `work` only if this instance gets the MariaDB named lock of job `name`: several API
// instances never run the same tick together (NVD calls, alerts). The lock lives on one dedicated
// connection and is released even when `work` throws. Resolves to { skipped: true } when another
// instance holds it.
export function withJobLock(name, work) {
	const lockName = `${process.env.DB_NAME}:${name}`;
	return database.withConnection(async connection => {
		const [{ acquired }] = await connection.query('SELECT GET_LOCK(?, 0) AS acquired', [lockName]);
		if (Number(acquired) !== 1) return { skipped: true };
		try {
			return await work();
		} finally {
			await connection.query('SELECT RELEASE_LOCK(?)', [lockName]);
		}
	});
}
