import authenticateUser from '../middleware/authenticate-user.js';
import requireRole from '../middleware/require-role.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

const ROLES = new Set(['admin', 'viewer']);
const parseUserID = value => (/^[1-9]\d{0,9}$/.test(value) ? Number(value) : undefined);

router.use(authenticateUser);

// Members of the caller's organization, never their secrets.
router.get('/', async (request, response) => {
	try {
		const users = await database.query('SELECT userID, username, firstname, lastname, role, isVerified FROM users WHERE orgID = ? ORDER BY userID', [request.user.orgID]);
		return response.status(200).send({ message: 'Users retrieved.', users: users.map(user => ({ ...user, isVerified: user.isVerified === 1 })) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to list users.' });
	}
});

// Change a member's role. The organization row is locked so concurrent demotions cannot leave it
// without any admin.
router.patch('/:id/role', requireRole('admin'), async (request, response) => {
	const userID = parseUserID(request.params.id);
	if (!userID) return response.status(400).send({ message: 'Error : Invalid user id.' });
	const role = request.body?.role;
	if (!ROLES.has(role)) return response.status(400).send({ message: 'Error : Invalid role.' });

	try {
		const outcome = await database.transaction(async connection => {
			await connection.query('SELECT orgID FROM organizations WHERE orgID = ? FOR UPDATE', [request.user.orgID]);
			const [target] = await connection.query('SELECT role FROM users WHERE userID = ? AND orgID = ?', [userID, request.user.orgID]);
			if (!target) return 'not-found';
			if (target.role === 'admin' && role !== 'admin') {
				const [{ admins }] = await connection.query('SELECT COUNT(*) AS admins FROM users WHERE orgID = ? AND role = ?', [request.user.orgID, 'admin']);
				if (Number(admins) <= 1) return 'last-admin';
			}
			await connection.query('UPDATE users SET role = ? WHERE userID = ?', [role, userID]);
			return 'updated';
		});

		if (outcome === 'not-found') return response.status(404).send({ message: 'Error : User not found.' });
		if (outcome === 'last-admin') return response.status(409).send({ message: 'Error : Last admin.' });
		return response.status(200).send({ message: 'Role updated.', userID, role });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to update role.' });
	}
});

export default router;
