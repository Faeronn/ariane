const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const accessSecret = process.env.JWT_SECRET;
const refreshSecret = process.env.JWT_REFRESH_SECRET;
if (!accessSecret) throw new Error('JWT_SECRET is missing');
if (!refreshSecret) throw new Error('JWT_REFRESH_SECRET is missing');

const validateToken = (request, response, next) => {
	const authHeader = request.headers['authorization'];
	if (!authHeader?.startsWith('Bearer ')) return response.status(401).send({ message: 'Error : A token is required to access this route.' });

	const token = authHeader.slice('Bearer '.length);
	try {
		jwt.verify(token, accessSecret, (error, decoded) => {
			if (error) return response.status(403).send({ message: 'Error : Token is not valid.' });

			request.user = decoded;
			return next();
		});
	} catch {
		return response.status(403).send({ message: 'Error : Token is not valid.' });
	}
};

function generateAccessToken(userInfo) {
	return jwt.sign(userInfo, accessSecret, { expiresIn: '1h' });
}

function generateRefreshToken() {
	return crypto.randomBytes(48).toString('base64url');
}

function hashToken(token) {
	return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = {
	hashToken,
	validateToken,
	generateAccessToken,
	generateRefreshToken
};