import mariadb from 'mariadb';

const pool = mariadb.createPool({
	host: process.env.DB_HOST,
	port: process.env.DB_PORT,
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	database: process.env.DB_NAME,
	connectionLimit: 5
});

async function query(sql, values) {
	let sqlConnection;

	try {
		sqlConnection = await pool.getConnection();
		return await sqlConnection.query(sql, values);
	} finally {
		if (sqlConnection) await sqlConnection.release();
	}
}

// Run `work(connection)` in one transaction: committed when it resolves, rolled back when it throws.
async function transaction(work) {
	const connection = await pool.getConnection();

	try {
		await connection.beginTransaction();
		const result = await work(connection);
		await connection.commit();
		return result;
	} catch (error) {
		await connection.rollback();
		throw error;
	} finally {
		await connection.release();
	}
}

async function end() {
	await pool.end();
}

export default { query, transaction, end };
