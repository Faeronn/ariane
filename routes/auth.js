import { generateAccessToken, generateRefreshToken, hashToken, hashVerificationCode } from '../utils/jwt.js';
import { sendVerificationEmail } from '../utils/mailer.js';
import sanitizeInput from '../utils/sanitizer.js';
import { signinPerIp, signinPerAccount, signupPerIp, verifyPerIp, refreshPerIp } from '../middleware/rate-limit.js';
import database from '../utils/database.js';
import crypto from 'node:crypto';
import express from 'express';
import bcrypt from 'bcrypt';
const router = express.Router();

const MAX_VERIFY_ATTEMPTS = 5;
const INVALID_CODE_MESSAGE = 'Error : Invalid verification code.';

router.post('/signin', signinPerIp, signinPerAccount, async (request, response) => {
	const username = sanitizeInput(request.body.username);
	const password = readPassword(request.body);
	if (!username || !password) return response.status(400).send({ message: 'Error : Missing credentials.' });

	try {
		const users = await database.query('SELECT * FROM users WHERE username = ?', [username]);
		if (users.length === 0) return response.status(401).send({ message: 'Error : Unable to sign in.' });

		const user = users[0];
		const bcryptResult = await passwordMatches(user, password);
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

router.post('/signup', signupPerIp, async (request, response) => {
	try {
		const firstname = sanitizeInput(request.body.firstname);
		const lastname = sanitizeInput(request.body.lastname);
		const username = sanitizeInput(request.body.username);
		const password = readPassword(request.body);

		if (!username || !password || !firstname || !lastname) return response.status(400).send({ message: 'Error : Missing credentials.' });
		if(!isUsernameValid(username)) return response.status(400).send({ message: 'Error : Invalid username.' });

		const domain = username.split('@')[1];
		const domainQuery = await database.query('SELECT orgID FROM domain WHERE domainName = ?', [domain]);
		if (domainQuery.length === 0) return response.status(403).send({ message: 'Error : Unable to signup.' });
		
		const hashedPassword = await bcrypt.hash(password, 10);

		const signupQuery = await database.query('INSERT INTO users (orgID, username, password, firstname, lastname) VALUES (?, ?, ?, ?, ?);', [domainQuery[0].orgID, username, hashedPassword, firstname, lastname]);
		if (signupQuery.affectedRows <= 0) return response.status(500).send({ message: 'Error : Unable to create User.' });

		const verificationCode = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
		const verificationQuery = await database.query('INSERT INTO verifications (userID, verificationCode, expiryDate) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR));', [signupQuery.insertId, hashVerificationCode(verificationCode)]);
		
		if (verificationQuery.affectedRows <= 0) return response.status(500).send({ message: 'Error : Unable to setup Verification.' });
		sendVerificationEmail(username, verificationCode);
		return response.status(200).send({ message: 'User created successfully.', user: {userID : signupQuery.insertId.toString(), userlogin : username } });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to signup User.'});
	}
});

// The first verified user of an organization without admin becomes its admin. The organization row
// is locked so two users verifying at once cannot both see "no admin yet".
async function promoteIfFirstAdmin(connection, userID) {
	const [user] = await connection.query('SELECT orgID FROM users WHERE userID = ?', [userID]);
	if (!user?.orgID) return;
	await connection.query('SELECT orgID FROM organizations WHERE orgID = ? FOR UPDATE', [user.orgID]);
	const admins = await connection.query('SELECT userID FROM users WHERE orgID = ? AND role = ? LIMIT 1', [user.orgID, 'admin']);
	if (admins.length === 0) await connection.query('UPDATE users SET role = ? WHERE userID = ?', ['admin', userID]);
}

// The code is checked against its own user only, within MAX_VERIFY_ATTEMPTS and before its expiry.
router.get('/verify', verifyPerIp, async (request, response) => {
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

		const stored = Buffer.from(String(rows[0].verificationCode));
		const given = Buffer.from(hashVerificationCode(verificationCode));
		const isMatch = stored.length === given.length && crypto.timingSafeEqual(stored, given);
		if (!isMatch) return response.status(400).send({ message: INVALID_CODE_MESSAGE });

		await database.transaction(async connection => {
			await connection.query('UPDATE users SET isVerified = 1 WHERE userID = ?', [userID]);
			await connection.query('DELETE FROM verifications WHERE verificationID = ?', [verificationID]);
			await promoteIfFirstAdmin(connection, userID);
		});
		return response.status(200).send({ message: 'Email address verified.' });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to verify email address.'});
	}
});

router.post('/refresh', refreshPerIp, async (request, response) => {
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

// An email address: local part with `+` addressing, a domain of one or more labels (subdomains
// allowed) ending with a 2 to 63 letter TLD, 254 characters at most.
const LOCAL_PART = /^[\w.%+-]{1,64}$/;
const DOMAIN_LABEL = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i;
const TLD = /^[a-z]{2,63}$/i;

function isUsernameValid(username) {
	if (username.length > 254) return false;
	const parts = username.split('@');
	if (parts.length !== 2 || !LOCAL_PART.test(parts[0])) return false;
	const labels = parts[1].split('.');
	return labels.length >= 2 && labels.slice(0, -1).every(label => DOMAIN_LABEL.test(label)) && TLD.test(labels.at(-1));
}

// The password as typed: never sanitized, bcrypt and parameterized queries need no escaping.
function readPassword(body) {
	return typeof body?.password === 'string' ? body.password : '';
}

// Accounts created before passwords stopped being sanitized hold a hash of the sanitized form:
// it is accepted once, then the hash is upgraded to the password as typed.
async function passwordMatches(user, password) {
	if (await bcrypt.compare(password, user.password)) return true;
	const legacy = sanitizeInput(password);
	if (legacy === password || !(await bcrypt.compare(legacy, user.password))) return false;
	await database.query('UPDATE users SET password = ? WHERE userID = ?', [await bcrypt.hash(password, 10), user.userID]);
	return true;
}

export default router;