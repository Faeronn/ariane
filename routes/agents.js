import authenticateAgent from '../middleware/authenticate-agent.js';
import { validateInventory } from '../utils/inventory.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

router.use(authenticateAgent);

// Store one inventory snapshot of the calling machine, atomically with its software rows.
router.post('/inventory', async (request, response) => {
	const { errors, inventory } = validateInventory(request.body);
	if (errors) return response.status(400).send({ message: 'Error : Invalid inventory.', errors });

	const { machineID } = request.machine;
	try {
		const snapshotID = await database.transaction(async connection => {
			const snapshot = await connection.query('INSERT INTO inventory_snapshot (machineID, collectedAt, receivedAt) VALUES (?, ?, UTC_TIMESTAMP())', [machineID, toSqlDateTime(inventory.collectedAt)]);
			const insertedID = Number(snapshot.insertId);
			if (inventory.software.length > 0) {
				await connection.batch('INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (?, ?, ?, ?)', inventory.software.map(({ vendor, name, version }) => [insertedID, vendor, name, version]));
			}
			await connection.query(`UPDATE machines SET hostname = COALESCE(NULLIF(?, ''), hostname), osFamily = ?, osVersion = NULLIF(?, ''), lastSeenAt = UTC_TIMESTAMP() WHERE machineID = ?`, [inventory.hostname ?? '', inventory.osFamily, inventory.osVersion ?? '', machineID]);
			return insertedID;
		});

		return response.status(201).send({ message: 'Inventory received.', snapshotID });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to store inventory.' });
	}
});

// DATETIME columns hold UTC; format explicitly so the driver does not apply the server's local offset.
function toSqlDateTime(date) {
	return date.toISOString().slice(0, 19).replace('T', ' ');
}

export default router;
