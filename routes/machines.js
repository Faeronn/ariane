import authenticateUser from '../middleware/authenticate-user.js';
import sanitizeInput from '../utils/sanitizer.js';
import database from '../utils/database.js';
import { hashToken } from '../utils/jwt.js';
import crypto from 'node:crypto';
import express from 'express';
const router = express.Router();

router.use(authenticateUser);

// DATETIME columns hold UTC: return them as ISO 8601 strings instead of driver-local Dates.
const isoUtc = column => `DATE_FORMAT(${column}, '%Y-%m-%dT%H:%i:%sZ')`;
const LATEST_SNAPSHOT = 'SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = m.machineID';

router.get('/', async (request, response) => {
	try {
		const machines = await database.query(`SELECT m.machineID, m.hostname, m.osFamily, m.osVersion, ${isoUtc('m.createdAt')} AS createdAt, ${isoUtc('m.lastSeenAt')} AS lastSeenAt, ${isoUtc('m.revokedAt')} AS revokedAt,
			(SELECT COUNT(*) FROM installed_software s WHERE s.snapshotID = (${LATEST_SNAPSHOT})) AS softwareCount
			FROM machines m ORDER BY m.machineID`);

		return response.status(200).send({ message: 'Machines retrieved.', machines: machines.map(machine => ({ ...machine, softwareCount: Number(machine.softwareCount) })) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to list machines.' });
	}
});

// One machine with the software of its latest snapshot.
router.get('/:id', async (request, response) => {
	const machineID = parseMachineID(request.params.id);
	if (!machineID) return response.status(400).send({ message: 'Error : Invalid machine id.' });

	try {
		const machines = await database.query(`SELECT m.machineID, m.hostname, m.osFamily, m.osVersion, ${isoUtc('m.createdAt')} AS createdAt, ${isoUtc('m.lastSeenAt')} AS lastSeenAt, ${isoUtc('m.revokedAt')} AS revokedAt,
			snap.snapshotID, ${isoUtc('snap.collectedAt')} AS collectedAt
			FROM machines m LEFT JOIN inventory_snapshot snap ON snap.snapshotID = (${LATEST_SNAPSHOT})
			WHERE m.machineID = ?`, [machineID]);
		if (machines.length === 0) return response.status(404).send({ message: 'Error : Machine not found.' });

		const { snapshotID, collectedAt, ...machine } = machines[0];
		const software = snapshotID ? await database.query('SELECT vendor, name, version FROM installed_software WHERE snapshotID = ? ORDER BY name, version', [snapshotID]) : [];

		return response.status(200).send({ message: 'Machine retrieved.', machine, ...(snapshotID && { snapshot: { snapshotID, collectedAt } }), software });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to retrieve machine.' });
	}
});

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
