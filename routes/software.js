import authenticateUser from '../middleware/authenticate-user.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

const MAX_ENTRIES = 500;

router.use(authenticateUser);

// Software of the organization's active machines (latest snapshot) that has no CPE yet, most
// widespread first: what blinds the vulnerability detection, and where an alias would help most.
router.get('/unmapped', async (request, response) => {
	try {
		const rows = await database.query(`SELECT s.vendor, s.name, s.version, COALESCE(sc.status, 'pending') AS status,
				DATE_FORMAT(sc.lastCheckedAt, '%Y-%m-%dT%H:%i:%sZ') AS lastCheckedAt, COUNT(DISTINCT m.machineID) AS machineCount
			FROM machines m
			INNER JOIN installed_software s ON s.snapshotID = (SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = m.machineID)
			LEFT JOIN software_cpe sc ON sc.ecosystem = '' AND sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
			WHERE m.orgID = ? AND m.revokedAt IS NULL AND (sc.status IS NULL OR sc.status <> 'matched')
			GROUP BY s.vendor, s.name, s.version, sc.status, sc.lastCheckedAt
			ORDER BY machineCount DESC, s.name, s.version
			LIMIT ?`, [request.user.orgID, MAX_ENTRIES]);

		const software = rows.map(row => ({ ...row, machineCount: Number(row.machineCount) }));
		return response.status(200).send({ message: 'Unmapped software retrieved.', software });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to list unmapped software.' });
	}
});

export default router;
