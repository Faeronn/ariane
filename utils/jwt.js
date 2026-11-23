import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

const accessSecret = process.env.JWT_ACCESS_SECRET;
const refreshSecret = process.env.JWT_REFRESH_SECRET;
if (!accessSecret) throw new Error('JWT_ACCESS_SECRET is missing');
if (!refreshSecret) throw new Error('JWT_REFRESH_SECRET is missing');

function generateAccessToken(userInfo) {
	return jwt.sign(userInfo, accessSecret, { expiresIn: '1h' });
}

// Returns the decoded payload; throws when the token is invalid or expired.
function verifyAccessToken(token) {
	return jwt.verify(token, accessSecret);
}

function generateRefreshToken() {
	return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token) {
	return crypto.createHash('sha256').update(token).digest('hex');
}

// Verification codes have only a million values, so a plain hash would be reversed at once: they
// are keyed with the refresh secret, which a database dump alone does not reveal.
function hashVerificationCode(code) {
	return crypto.createHmac('sha256', process.env.JWT_REFRESH_SECRET).update(code).digest('hex');
}

export {
	hashToken,
	hashVerificationCode,
	verifyAccessToken,
	generateAccessToken,
	generateRefreshToken
};
