const { sendVerificationEmail } = require('../utils/mailer');
const sanitizeInput = require('../utils/sanitizer');
const { generateAccessToken, generateRefreshToken, hashToken } = require('../utils/jwt');
const database = require('../utils/database');
const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

//TODO: Implement a logger and wrap [return response.status().send()]
//Maybe a custom util instead of the plain logger ?

router.post('/signin', async (request, response) => {
	const username = sanitizeInput(request.body.username);
	const password = sanitizeInput(request.body.password);
	if (!username || !password) return response.status(400).send({ message: 'Error : Missing credentials.' });

	try {
		const users = await database.query('SELECT * FROM users WHERE username = ?', [username]);
    	if (users.length === 0) return response.status(401).send({ message: 'Error : Unable to sign in.' });

		const user = users[0];
		const bcryptResult = await bcrypt.compare(password, user.password);
		if (!bcryptResult) return response.status(401).send({ message: 'Error : Unable to sign in.' });
		if (user.isVerified !== 1) return response.status(401).send({ message: 'Error : Unable to sign in.' });

		const token = generateAccessToken({ username });
		const refreshToken = generateRefreshToken();
   		const refreshHash = hashToken(refreshToken);
		await database.query('INSERT INTO refresh_token (userID, tokenHash, expiresAt, createdAt) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY), UTC_TIMESTAMP())', [user.userID, refreshHash]);

		return response.status(200).send({ message: 'Login successful!', accesstoken: token, refreshToken: refreshToken, user: {userID: user.userID, username: user.username, firstname: user.firstname, lastname: user.lastname}, expiresIn: 3600 });
	} catch { // TODO : catch the error & log it
		return response.status(500).send({ message: 'Error : Unable to sign in.' });
	}
});

router.post('/signup', async (request, response) => {
	try {
		const firstname = sanitizeInput(request.body.firstname);
		const lastname = sanitizeInput(request.body.lastname);
		const username = sanitizeInput(request.body.username);
		const password = sanitizeInput(request.body.password);

		if (!username || !password || !firstname || !lastname) return response.status(400).send({ message: 'Error : Missing credentials.' });
		if(!isUsernameValid(username)) return response.status(400).send({ message: 'Error : Invalid username.' });

		const domain = username.split('@')[1];
		const domainQuery = await database.query('SELECT * FROM domain WHERE domainName = ?', [domain]);
		if (domainQuery.length === 0) return response.status(403).send({ message: 'Error : Unable to signup.' });
		
		const hashedPassword = await bcrypt.hash(password, 10);

		const signupQuery = await database.query('INSERT INTO users (username, password, firstname, lastname) VALUES (?, ?, ?, ?);', [username, hashedPassword, firstname, lastname]);
		if (signupQuery.affectedRows <= 0) return response.status(500).send({ message: 'Error : Unable to create User.' });

		const verificationCode = Array.from(crypto.getRandomValues(new Uint8Array(6)), x => x % 10).join('');
		const timeZoneOffset = new Date().getTimezoneOffset() * 60_000;
		const rawExpiryDate = new Date((Date.now() - timeZoneOffset) + 3_600_000).toISOString();
		const expiryDate = rawExpiryDate.replace('T', ' ').slice(0, 19);
		const verificationQuery = await database.query('INSERT INTO verifications (userID, verificationCode, expiryDate) VALUES (?, ?, ?);', [signupQuery.insertId, verificationCode, expiryDate]);
		
		if (verificationQuery.affectedRows <= 0) return response.status(500).send({ message: 'Error : Unable to setup Verification.' });
		sendVerificationEmail(username, verificationCode);
		return response.status(200).send({ message: 'User created successfully.', user: {userID : signupQuery.insertId.toString(), userlogin : username } });
	} catch { // TODO : catch the error & log it
		return response.status(500).send({ message: 'Error : Unable to signup User.'});
	}
});

//TODO : Security Hardening - Link the user to the code to stop bruteforce attacks to just activate all accounts
router.post('/verify/:code', async (request, response) => {
	const verificationCode = String(sanitizeInput(request.params.code) ?? '').trim();
	if (!verificationCode) return response.status(400).send({ message: 'Error : Missing information.' });
	if (!/^\d{6}$/.test(verificationCode)) return response.status(400).send({ message: 'Error : Invalid verificationCode.' });

	try {
		const result = await database.query('SELECT * FROM verifications WHERE verificationCode = ?', [verificationCode]); //This is BAD.
		if(result.length === 0) return response.status(404).send({ message: 'Error : Invalid verificationCode.' });

		await database.query('UPDATE users SET isVerified = 1 WHERE userID = ?', [result[0].userID]);
		await database.query('DELETE FROM verifications WHERE verificationCode = ?', [verificationCode]);
		return response.status(200).send({ message: 'Valid verificationId.'});
	} catch { // TODO : catch the error & log it
		return response.status(500).send({ message: 'Error : Unable to verify email address.'});
	}
});

router.post('/refresh', async (request, response) => {
	const refreshToken = String(sanitizeInput(request.body.refreshToken) ?? '').trim();
	if (!refreshToken) return response.status(400).send({ message: 'Error : Missing information.' });

	try {
		const tokenHash = hashToken(refreshToken);
		const rows = await database.query(`SELECT rt.userID, u.username, u.isVerified FROM refresh_token rt INNER JOIN users u ON u.userID = rt.userID WHERE rt.tokenHash = ? AND rt.expiresAt > UTC_TIMESTAMP() LIMIT 1`, [tokenHash]);
		if (rows.length === 0) return response.status(401).send({ message: 'Error : Unable to refresh token.' });

		const { userID, username, isVerified } = rows[0];
		if (isVerified !== 1) return response.status(401).send({ message: 'Error : Unable to refresh token.' });

		const newRefreshToken = generateRefreshToken();
		const newRefreshHash = hashToken(newRefreshToken);

		await database.query('DELETE FROM refresh_token WHERE tokenHash = ?', [tokenHash]);
		await database.query(`INSERT INTO refresh_token (userID, tokenHash, expiresAt, createdAt) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY), UTC_TIMESTAMP())`, [userID, newRefreshHash] );

		const accessToken = generateAccessToken({ username });
		return response.status(200).send({ message: 'Token refreshed!', accesstoken: accessToken, refreshToken: newRefreshToken, expiresIn: 3600 });
	} catch { // TODO : catch the error & log it
		return response.status(500).send({ message: 'Error : Unable to refresh token.' });
	}
});

router.post('/signout', async (request, response) => {
	const refreshToken = String(sanitizeInput(request.body.refreshToken) ?? '').trim();
	if (!refreshToken) return response.status(400).send({ message: 'Error : Missing information.' });

	try {
		const tokenHash = hashToken(refreshToken);
		await database.query('DELETE FROM refresh_token WHERE tokenHash = ?', [tokenHash]);

		return response.status(200).send({ message: 'Signed out successfully.' });
	} catch { // TODO : catch the error & log it
		return response.status(500).send({ message: 'Error : Unable to sign out.' });
	}
});

function isUsernameValid(username) {
	return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,5}$/.test(username);
}

module.exports = router;