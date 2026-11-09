import { generateAccessToken, generateRefreshToken, hashToken } from '../utils/jwt.js';
import { sendVerificationEmail } from '../utils/mailer.js';
import sanitizeInput from '../utils/sanitizer.js';
import database from '../utils/database.js';
import crypto from 'node:crypto';
import express from 'express';
import bcrypt from 'bcrypt';
const router = express.Router();

const MAX_VERIFY_ATTEMPTS = 5;
const INVALID_CODE_MESSAGE = 'Error : Invalid verification code.';

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
	} catch (error) {
		request.log.error(error);
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

		const verificationCode = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
		const verificationQuery = await database.query('INSERT INTO verifications (userID, verificationCode, expiryDate) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR));', [signupQuery.insertId, verificationCode]);
		
		if (verificationQuery.affectedRows <= 0) return response.status(500).send({ message: 'Error : Unable to setup Verification.' });
		sendVerificationEmail(username, verificationCode);
		return response.status(200).send({ message: 'User created successfully.', user: {userID : signupQuery.insertId.toString(), userlogin : username } });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to signup User.'});
	}
});

// The code is checked against its own user only, within MAX_VERIFY_ATTEMPTS and before its expiry.
router.get('/verify', async (request, response) => {
	const username = typeof request.query.username === 'string' ? sanitizeInput(request.query.username).trim() : '';
	const verificationCode = typeof request.query.code === 'string' ? request.query.code.trim() : '';
	if (!username || !verificationCode) return response.status(400).send({ message: 'Error : Missing information.' });
	if (!/^\d{6}$/.test(verificationCode)) return response.status(400).send({ message: INVALID_CODE_MESSAGE });

	try {
		const rows = await database.query('SELECT v.verificationID, v.userID, v.verificationCode FROM verifications v INNER JOIN users u ON u.userID = v.userID WHERE u.username = ?', [username]);
		if (rows.length === 0) return response.status(400).send({ message: INVALID_CODE_MESSAGE });
		const { verificationID, userID } = rows[0];

		// Count the attempt atomically before comparing, so parallel guesses cannot exceed the limit.
		const attempt = await database.query('UPDATE verifications SET attempts = attempts + 1 WHERE verificationID = ? AND attempts < ? AND expiryDate > UTC_TIMESTAMP()', [verificationID, MAX_VERIFY_ATTEMPTS]);
		if (attempt.affectedRows === 0) {
			await database.query('DELETE FROM verifications WHERE verificationID = ?', [verificationID]);
			return response.status(410).send({ message: 'Error : Verification code expired.' });
		}

		const isMatch = crypto.timingSafeEqual(Buffer.from(rows[0].verificationCode), Buffer.from(verificationCode));
		if (!isMatch) return response.status(400).send({ message: INVALID_CODE_MESSAGE });

		await database.query('UPDATE users SET isVerified = 1 WHERE userID = ?', [userID]);
		await database.query('DELETE FROM verifications WHERE verificationID = ?', [verificationID]);
		return response.status(200).send({ message: 'Email address verified.' });
	} catch (error) {
		request.log.error(error);
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
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to refresh token.' });
	}
});

router.post('/logout', async (request, response) => {
	const refreshToken = String(sanitizeInput(request.body.refreshToken) ?? '').trim();
	if (!refreshToken) return response.status(400).send({ message: 'Error : Missing information.' });

	try {
		const tokenHash = hashToken(refreshToken);
		await database.query('DELETE FROM refresh_token WHERE tokenHash = ?', [tokenHash]);

		return response.status(200).send({ message: 'Signed out successfully.' });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to sign out.' });
	}
});

function isUsernameValid(username) {
	return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,5}$/.test(username);
}

export default router;