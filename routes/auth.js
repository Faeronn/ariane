const { sendVerificationEmail } = require('../utils/mailer');
const sanitizeInput = require('../utils/sanitizer');
const { generateAccessToken, generateRefreshToken, hashToken } = require('../utils/jwt');
const db = require('../utils/database');
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

router.post('/signin', async (req, res) => {
	const username = sanitizeInput(req.body.username);
	const password = sanitizeInput(req.body.password);
	if (!username || !password) return res.status(400).send({ message: 'Error : Missing credentials.' });

	try {
		const users = await db.query('SELECT * FROM users WHERE username = ?', [username]);
    	if (!(users.length > 0)) return res.status(401).send({ message: 'Invalid credentials!' });

		const user = users[0];
		const bcryptResult = await bcrypt.compare(password, user.password);
		if (!bcryptResult) return res.status(401).send({ message: 'Invalid credentials!' });
		if (!(user.isVerified === 1)) return res.status(401).send({ message: 'You must verify email !' });

		const token = generateAccessToken({ username });
		const refreshToken = generateRefreshToken();
   		const refreshHash = hashToken(refreshToken);
		await db.query('INSERT INTO refresh_token (userID, tokenHash, expiresAt, createdAt) VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY), UTC_TIMESTAMP())', [user.userID, refreshHash]);

		return res.status(200).send({ message: 'Login successful!', accesstoken: token, refreshToken: refreshToken, user: {userID: user.userID, username: user.username, firstname: user.firstname, lastname: user.lastname}, expiresIn: 3600 });
	} catch(error) {
		return res.status(500).send({ message: 'Error : ' + error });
	}
});

router.post('/signup', async (req, res) => {
	try {
		const firstname = sanitizeInput(req.body.firstname);
		const lastname = sanitizeInput(req.body.lastname);
		const username = sanitizeInput(req.body.username);
		const password = sanitizeInput(req.body.password);

		if (!username || !password || !firstname || !lastname) return res.status(400).send({ message: 'Error : Missing credentials.' });
		if(!isUsernameValid(username)) return res.status(400).send({ message: 'Error : Invalid username.' });

		const domain = username.split('@')[1];
		const domainQuery = await db.query('SELECT * FROM domain WHERE domainName = ?', [domain]);
		if (!(domainQuery.length > 0)) return res.status(403).send({ message: 'Error : Unable to signup.' });
		
		const hashedPassword = await bcrypt.hash(password, 10);

		const signupQuery = await db.query('INSERT INTO users (username, password, firstname, lastname) VALUES (?, ?, ?, ?);', [username, hashedPassword, firstname, lastname]);
		if (!(signupQuery.affectedRows > 0)) return res.status(500).send({ message: 'Error : Unable to create User.' });

		const verificationCode = Array.from(crypto.getRandomValues(new Uint8Array(6)), x => x % 10).join('');
		const timeZoneOffset = new Date().getTimezoneOffset() * 60000;
		const rawExpiryDate = new Date((Date.now() - timeZoneOffset) + 3600000).toISOString();
		const expiryDate = rawExpiryDate.replace('T', ' ').substring(0, 19);
		const verificationQuery = await db.query('INSERT INTO verifications (userID, verificationCode) VALUES (?, ?);', [signupQuery.insertId, verificationCode]);
		
		if (!(verificationQuery.affectedRows > 0)) return res.status(500).send({ message: 'Error : Unable to setup Verification.' });
		sendVerificationEmail(username, verificationCode);
		return res.status(200).send({ message: 'User created successfully.', user: {userID : signupQuery.insertId.toString(), userlogin : username } });
	} catch(error) {
		return res.status(500).send({ message: 'Error : ' + error });
	}
});

router.post('/verify/:code', async (req, res) => {
	const verificationCode = String(sanitizeInput(req.params.code) ?? '').trim();
	if (!verificationCode) return res.status(400).send({ message: 'Error : Missing information.' });
	if (!/^\d{6}$/.test(verificationCode)) return res.status(400).send({ message: 'Error : Invalid verificationCode.' });

	try {
		const result = await db.query('SELECT * FROM verifications WHERE verificationCode = ?', [verificationCode]);
		if(result.length === 0) return res.status(404).send({ message: 'Error : Invalid verificationCode.' });

		await db.query('UPDATE users SET isVerified = 1 WHERE userID = ?', [result[0].userID]);
		await db.query('DELETE FROM verifications WHERE verificationCode = ?', [verificationCode]);
		return res.status(200).send({ message: 'Valid verificationId.'});
	} catch (err) {
		return res.status(500).send({ message: 'Error : Unable to verify email address.' + err});
	}
});

router.post('/refresh', async (req, res) => {
	//TODO : {refreshToken} ⇒ {accessToken}
	return res.status(500).send({ message: 'Error : Endpoint not yet implemented.'});
});

function isUsernameValid(username) {
	return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,5}$/.test(username);
}

module.exports = router;