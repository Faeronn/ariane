import authenticateUser from '../middleware/authenticate-user.js';
import sanitizeInput from '../utils/sanitizer.js';
import database from '../utils/database.js';
import { hashToken } from '../utils/jwt.js';
import crypto from 'node:crypto';
import express from 'express';
const router = express.Router();

router.use(authenticateUser);

// Enroll a machine. The plain agent key is returned once; only its hash is stored.
router.post('/', async (request, response) => {
	const hostname = typeof request.body?.hostname === 'string' ? sanitizeInput(request.body.hostname).trim() : '';
	if (!isHostnameValid(hostname)) return response.status(400).send({ message: 'Error : Invalid hostname.' });

	try {
		const apiKey = crypto.randomBytes(32).toString('base64url');
		const result = await database.query('INSERT INTO machines (hostname, apiKeyHash, createdBy, createdAt) SELECT ?, ?, userID, UTC_TIMESTAMP() FROM users WHERE username = ?', [hostname, hashToken(apiKey), request.user.username]);
		if (result.affectedRows === 0) return response.status(401).send({ message: 'Error : Unknown user.' });

		return response.status(201).send({ message: 'Machine enrolled.', machineID: Number(result.insertId), apiKey });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to enroll machine.' });
	}
});

// Revoke a machine: its agent key stops working. Idempotent on an already revoked machine.
router.delete('/:id', async (request, response) => {
	const machineID = parseMachineID(request.params.id);
	if (!machineID) return response.status(400).send({ message: 'Error : Invalid machine id.' });

	try {
		const machines = await database.query('SELECT machineID FROM machines WHERE machineID = ?', [machineID]);
		if (machines.length === 0) return response.status(404).send({ message: 'Error : Machine not found.' });

		await database.query('UPDATE machines SET revokedAt = UTC_TIMESTAMP() WHERE machineID = ? AND revokedAt IS NULL', [machineID]);
		return response.status(200).send({ message: 'Machine revoked.' });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to revoke machine.' });
	}
});

function isHostnameValid(hostname) {
	return hostname.length > 0 && hostname.length <= 255 && /^[\w.-]+$/.test(hostname);
}

function parseMachineID(value) {
	return /^[1-9]\d{0,9}$/.test(value) ? Number(value) : undefined;
}

export default router;
