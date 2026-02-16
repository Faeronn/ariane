const mariadb = require('mariadb');

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
		if (sqlConnection) sqlConnection.end();
	}
}

async function getHashedPasswordForUser(username) {
	try {
		const result = await query('SELECT password FROM users WHERE username=?', [username]);
		
		if (result.length > 0) return result[0].password;
		else return '';
	} catch (error) {
		console.error('Error in getHashedPasswordForUser:', error);
		throw error;
	}
}


module.exports = {
	query,
	getHashedPasswordForUser
};
