import authenticateUser from '../middleware/authenticate-user.js';
import database from '../utils/database.js';
import { applicationVulnerabilities } from '../utils/vulnerabilities.js';
import express from 'express';
const router = express.Router();

router.use(authenticateUser);

// DATETIME columns hold UTC: return them as ISO 8601 strings instead of driver-local Dates.
const isoUtc = column => `DATE_FORMAT(${column}, '%Y-%m-%dT%H:%i:%sZ')`;
const LATEST_SNAPSHOT = 'SELECT MAX(snapshotID) FROM application_snapshot WHERE applicationID = a.applicationID';
const APPLICATION_COLUMNS = `a.applicationID, a.name, a.path, a.machineID, m.hostname, ${isoUtc('a.createdAt')} AS createdAt, ${isoUtc('a.lastSeenAt')} AS lastSeenAt`;
// Like machines, another organization's application answers 404 as an unknown id.

const parseApplicationID = value => (/^[1-9]\d{0,9}$/.test(value) ? Number(value) : undefined);

// The organization's applications with the size of their latest dependency snapshot.
router.get('/', async (request, response) => {
	try {
		const applications = await database.query(`SELECT ${APPLICATION_COLUMNS},
			(SELECT COUNT(*) FROM application_dependency d WHERE d.snapshotID = (${LATEST_SNAPSHOT})) AS packages,
			(SELECT COUNT(*) FROM application_dependency d WHERE d.snapshotID = (${LATEST_SNAPSHOT}) AND d.direct = 1) AS directPackages
			FROM applications a INNER JOIN machines m ON m.machineID = a.machineID
			WHERE a.orgID = ? ORDER BY m.hostname, a.name`, [request.user.orgID]);
		return response.status(200).send({ message: 'Applications retrieved.', applications: applications.map(application => ({ ...application, packages: Number(application.packages), directPackages: Number(application.directPackages) })) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to list applications.' });
	}
});

// The application of the caller's organization, or undefined.
async function findApplication(request) {
	const applicationID = parseApplicationID(request.params.id);
	if (!applicationID) return { invalid: true };
	const [application] = await database.query(`SELECT ${APPLICATION_COLUMNS}, (${LATEST_SNAPSHOT}) AS snapshotID
		FROM applications a INNER JOIN machines m ON m.machineID = a.machineID
		WHERE a.applicationID = ? AND a.orgID = ?`, [applicationID, request.user.orgID]);
	return { application };
}

// One application with the packages of its latest snapshot.
router.get('/:id', async (request, response) => {
	try {
		const { invalid, application } = await findApplication(request);
		if (invalid) return response.status(400).send({ message: 'Error : Invalid application id.' });
		if (!application) return response.status(404).send({ message: 'Error : Application not found.' });

		const { snapshotID, ...details } = application;
		const packages = await database.query('SELECT ecosystem, name, version, direct, dev FROM application_dependency WHERE snapshotID = ? ORDER BY ecosystem, name, version', [snapshotID]);
		return response.status(200).send({ message: 'Application retrieved.', application: details, packages: packages.map(item => ({ ...item, direct: Boolean(item.direct), dev: Boolean(item.dev) })) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to retrieve application.' });
	}
});

// Vulnerabilities of the latest dependencies, highest CVSS first; `unscanned`: packages still
// waiting for their OSV check (or Packagist's, for Composer).
router.get('/:id/vulns', async (request, response) => {
	try {
		const { invalid, application } = await findApplication(request);
		if (invalid) return response.status(400).send({ message: 'Error : Invalid application id.' });
		if (!application) return response.status(404).send({ message: 'Error : Application not found.' });

		const [vulnerabilities, [{ unscanned }]] = await Promise.all([
			applicationVulnerabilities(application.applicationID),
			database.query(`SELECT COUNT(*) AS unscanned FROM application_dependency d
				INNER JOIN package_vuln_key k ON k.ecosystem = d.ecosystem AND k.name = d.name AND k.version = d.version
				WHERE d.snapshotID = ? AND (k.status = 'pending' OR (k.ecosystem = 'Packagist' AND k.packagistCheckedAt IS NULL))`, [application.snapshotID])
		]);
		return response.status(200).send({ message: 'Vulnerabilities retrieved.', vulnerabilities, unscanned: Number(unscanned) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to retrieve vulnerabilities.' });
	}
});

export default router;
