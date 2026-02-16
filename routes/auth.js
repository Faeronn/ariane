const { sendVerificationEmail } = require('../utils/mailer');
const sanitizeInput = require('../utils/sanitizer');
const { generateAccessToken } = require('../utils/jwt');
const db = require('../utils/database');
const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();

router.post('/signin', async (req, res) => {
	const username = sanitizeInput(req.body.username);
	const password = sanitizeInput(req.body.password);
	if (!username || !password) return res.status(400).send({ message: 'Error : Missing credentials.' });
	//TODO : Add refreshToken
	try {
		const hashedPassword = await db.getHashedPasswordForUser(username);
		const bcryptResult = await bcrypt.compare(password, hashedPassword);
		if (!bcryptResult) return res.status(401).send({ message: 'Invalid credentials!' });

		const verifiedQuery = await db.query('SELECT isVerified FROM users WHERE username = ?', [username]);
		if (!(verifiedQuery.length > 0)) return res.status(401).send({ message: 'You must verify email !' });
		if (!(verifiedQuery[0].isVerified === 1)) return res.status(401).send({ message: 'You must verify email !' });

		const token = generateAccessToken({ username });
		const userDetails = await getUserDetails(username);
		const timeZoneOffset = new Date().getTimezoneOffset() * 60000;
		const expiryDate = new Date((Date.now() - timeZoneOffset) + 3600000).toISOString();
		return res.status(200).send({ message: 'Login successful!', token: token, user: userDetails, expiryDate: expiryDate });
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

		const verificationCode = generateVerificationNumber();
		const timeZoneOffset = new Date().getTimezoneOffset() * 60000;
		const rawExpiryDate = new Date((Date.now() - timeZoneOffset) + 3600000).toISOString();
		const expiryDate = rawExpiryDate.replace('T', ' ').substring(0, 19);
		const verificationQuery = await db.query('INSERT INTO verifications (userId, verificationCode) VALUES (?, ?);', [signupQuery.insertId, verificationCode]);
		
		if (!(verificationQuery.affectedRows > 0)) return res.status(500).send({ message: 'Error : Unable to setup Verification.' });
		sendVerificationEmail(username, verificationCode);
		return res.status(200).send({ message: 'User created successfully.', user: {userId : signupQuery.insertId.toString(), userlogin : username } });
	} catch(error) {
		return res.status(500).send({ message: 'Error : ' + error });
	}
});

//TODO : Get rid of this shit show, replace by post & use a code instead of a link => see mailer.js
router.get('/verify/:code', async (req, res) => {
	const verificationCode = sanitizeInput(req.params.code);
	if (!verificationCode) return res.status(400).send({ message: 'Error : Missing information.' });
	if (!isVerificationNumberValid(verificationCode)) return res.status(400).send({ message: 'Error : Invalid verificationCode.' });

	try {
		const result = await db.query('SELECT * FROM verifications WHERE verificationCode = ?', [verificationCode]);
		
		if (result.length > 0) {
			await db.query('UPDATE users SET isVerified = 1 WHERE userId = ?', [result[0].userId]);
			await db.query('DELETE FROM verifications WHERE verificationCode = ?', [verificationCode]);
			return res.status(200).send({ message: 'Valid verificationId.'});
		}
		else res.status(404).send({ message: 'Error : Invalid verificationCode.' });
	} catch (err) {
		return res.status(500).send({ message: 'Error : Unable to verify email.'});
	}
});

router.post('/refresh', async (req, res) => {
	//TODO : {refreshToken} ⇒ {accessToken}
	return res.status(500).send({ message: 'Error : Endpoint not yet implemented.'});
});


function generateVerificationNumber() {
	let key = '';
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

	for (let i = 0; i < 20; i++) {
		if (i > 0 && i % 5 === 0) key += '-';
		key += chars.charAt(Math.floor(Math.random() * chars.length));
	}

	return key;
}

async function getUserDetails(username) {
	const userDetailsQuery = await db.query('SELECT * FROM users WHERE username = ?', [username]);
	if (!(userDetailsQuery.length > 0)) return {};

	return userDetailsQuery[0];
}

function isUsernameValid(username) {
	const regex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,5}$/;
	return regex.test(username);
}

function isVerificationNumberValid(verificationCode) {
	const regex = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;
	return regex.test(verificationCode);
}

module.exports = router;