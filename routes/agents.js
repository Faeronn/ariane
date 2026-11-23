import authenticateAgent from '../middleware/authenticate-agent.js';
import { validateInventory } from '../utils/inventory.js';
import { validateApplication } from '../utils/application.js';
import { softwareKeyOf } from '../utils/package-key.js';
import { inventoryPerMachine, applicationsPerMachine } from '../middleware/rate-limit.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

router.use(authenticateAgent);

// Store one inventory snapshot of the calling machine, atomically with its software rows.
router.post('/inventory', inventoryPerMachine, async (request, response) => {
	const { errors, inventory } = validateInventory(request.body);
	if (errors) return response.status(400).send({ message: 'Error : Invalid inventory.', errors });

	const { machineID } = request.machine;
	try {
		const snapshotID = await database.transaction(async connection => {
			const snapshot = await connection.query('INSERT INTO inventory_snapshot (machineID, collectedAt, receivedAt) VALUES (?, ?, UTC_TIMESTAMP())', [machineID, toSqlDateTime(inventory.collectedAt)]);
			const insertedID = Number(snapshot.insertId);
			if (inventory.software.length > 0) {
				await connection.batch('INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (?, ?, ?, ?)', inventory.software.map(({ vendor, name, version }) => [insertedID, vendor, name, version]));
				// New software keys wait as `pending` for the CPE resolver job; the request never calls NVD.
				await connection.batch('INSERT IGNORE INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', inventory.software.map(({ vendor, name, version }) => [vendor, name, version]));
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

// Register one application of the calling machine with its lockfiles: a new snapshot of its exact
// packages. Package keys new to Ariane wait as `pending` for the OSV job; the request never calls OSV.
router.post('/applications', applicationsPerMachine, async (request, response) => {
	const { errors, application } = validateApplication(request.body);
	if (errors) return response.status(400).send({ message: 'Error : Invalid application.', errors });

	const { machineID } = request.machine;
	try {
		const { applicationID, snapshotID } = await database.transaction(async connection => {
			await connection.query(`INSERT INTO applications (orgID, machineID, name, path, createdAt, lastSeenAt)
				SELECT orgID, machineID, ?, NULLIF(?, ''), UTC_TIMESTAMP(), UTC_TIMESTAMP() FROM machines WHERE machineID = ?
				ON DUPLICATE KEY UPDATE path = VALUES(path), lastSeenAt = VALUES(lastSeenAt)`, [application.name, application.path ?? '', machineID]);
			const [{ applicationID: id }] = await connection.query('SELECT applicationID FROM applications WHERE machineID = ? AND name = ?', [machineID, application.name]);
			const snapshot = await connection.query('INSERT INTO application_snapshot (applicationID, receivedAt) VALUES (?, UTC_TIMESTAMP())', [id]);
			const insertedID = Number(snapshot.insertId);
			if (application.packages.length > 0) {
				const rows = application.packages.map(({ ecosystem, name, version }) => [ecosystem, name, version]);
				await connection.batch('INSERT INTO application_dependency (snapshotID, ecosystem, name, version, direct, dev) VALUES (?, ?, ?, ?, ?, ?)', application.packages.map(({ ecosystem, name, version, direct, dev }) => [insertedID, ecosystem, name, version, direct, dev]));
				await connection.batch('INSERT IGNORE INTO package_vuln_key (ecosystem, name, version) VALUES (?, ?, ?)', rows);
			}
			// Direct dependencies also go to the NVD resolver, as software keys.
			const direct = application.packages.filter(item => item.direct);
			if (direct.length > 0) {
				await connection.batch('INSERT IGNORE INTO software_cpe (vendor, name, version, ecosystem, packageName) VALUES (?, ?, ?, ?, ?)',
				direct.map(item => {
					const key = softwareKeyOf(item);
					return [key.vendor, key.name, key.version, item.ecosystem, item.name];
				}));
			}
			return { applicationID: id, snapshotID: insertedID };
		});

		return response.status(201).send({ message: 'Application received.', applicationID, snapshotID, packages: application.packages.length });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to store application.' });
	}
});

// DATETIME columns hold UTC; format explicitly so the driver does not apply the server's local offset.
function toSqlDateTime(date) {
	return date.toISOString().slice(0, 19).replace('T', ' ');
}

export default router;
