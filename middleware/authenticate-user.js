import { verifyAccessToken } from '../utils/jwt.js';

// Requires a valid `Authorization: Bearer <access token>`; sets request.user.
export default function authenticateUser(request, response, next) {
	const authHeader = request.headers['authorization'];
	if (!authHeader?.startsWith('Bearer ')) return response.status(401).send({ message: 'Error : A token is required to access this route.' });

	try {
		request.user = verifyAccessToken(authHeader.slice('Bearer '.length));
	} catch {
		return response.status(403).send({ message: 'Error : Token is not valid.' });
	}
	return next();
}
