import { verifyAccessToken } from '../utils/jwt.js';
import database from '../utils/database.js';

// Requires a valid `Authorization: Bearer <access token>`; sets request.user to
// { username, userID, orgID, role }. Organization and role are read from the database on every
// request, so a role change or a deleted account takes effect at once, not at token expiry.
export default async function authenticateUser(request, response, next) {
	const authHeader = request.headers['authorization'];
	if (!authHeader?.startsWith('Bearer ')) return response.status(401).send({ message: 'Error : A token is required to access this route.' });

	let payload;
	try {
		payload = verifyAccessToken(authHeader.slice('Bearer '.length));
	} catch {
		return response.status(403).send({ message: 'Error : Token is not valid.' });
	}

	const [user] = await database.query('SELECT userID, orgID, role FROM users WHERE username = ?', [payload.username]);
	if (!user) return response.status(401).send({ message: 'Error : Unknown user.' });
	if (!user.orgID) return response.status(403).send({ message: 'Error : No organization.' });

	request.user = { username: payload.username, userID: user.userID, orgID: user.orgID, role: user.role };
	return next();
}
