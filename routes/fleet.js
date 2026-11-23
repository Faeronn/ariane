import authenticateUser from '../middleware/authenticate-user.js';
import { machineVulnerabilities } from '../utils/vulnerabilities.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

const STALE_AFTER_DAYS = 7;
const TOP_CVES = 10;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

router.use(authenticateUser);

async function machineCounts(orgID) {
	const [row] = await database.query(`SELECT COUNT(*) AS total, COUNT(*) - COUNT(revokedAt) AS active, COUNT(revokedAt) AS revoked,
		SUM(revokedAt IS NULL AND (lastSeenAt IS NULL OR lastSeenAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))) AS stale
		FROM machines WHERE orgID = ?`, [STALE_AFTER_DAYS, orgID]);
	return { total: Number(row.total), active: Number(row.active), revoked: Number(row.revoked), stale: Number(row.stale ?? 0) };
}

// Distinct CVEs by severity, affected machines and the most widespread CVEs over active machines,
// with the same rules as GET /machines/:id/vulns (platform filter included).
async function vulnerabilityFigures(orgID) {
	const machines = await database.query('SELECT machineID FROM machines WHERE orgID = ? AND revokedAt IS NULL', [orgID]);
	const cves = new Map();
	let affectedMachines = 0;
	for (const { machineID } of machines) {
		const vulnerabilities = await machineVulnerabilities(machineID);
		if (vulnerabilities.length > 0) affectedMachines += 1;
		for (const { cveID, severity, cvssScore } of vulnerabilities) {
			if (!cves.has(cveID)) cves.set(cveID, { cveID, severity, cvssScore, machines: 0 });
			cves.get(cveID).machines += 1;
		}
	}

	const bySeverity = Object.fromEntries(SEVERITIES.map(severity => [severity, 0]));
	for (const { severity } of cves.values()) bySeverity[SEVERITIES.includes(severity) ? severity : 'UNKNOWN'] += 1;
	const topCves = [...cves.values()].toSorted((left, right) => right.machines - left.machines || (right.cvssScore ?? -1) - (left.cvssScore ?? -1) || left.cveID.localeCompare(right.cveID)).slice(0, TOP_CVES);
	return { total: cves.size, bySeverity, affectedMachines, topCves };
}

// Applications registered on the organization's active machines.
async function applicationCount(orgID) {
	const [{ total }] = await database.query(`SELECT COUNT(*) AS total FROM applications a
		INNER JOIN machines m ON m.machineID = a.machineID
		WHERE a.orgID = ? AND m.revokedAt IS NULL`, [orgID]);
	return { total: Number(total) };
}

async function unmappedCount(orgID) {
	const [{ unmapped }] = await database.query(`SELECT COUNT(DISTINCT s.vendor, s.name, s.version) AS unmapped
		FROM machines m
		INNER JOIN installed_software s ON s.snapshotID = (SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = m.machineID)
		LEFT JOIN software_cpe sc ON sc.ecosystem = '' AND sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
		WHERE m.orgID = ? AND m.revokedAt IS NULL AND (sc.status IS NULL OR sc.status <> 'matched')`, [orgID]);
	return Number(unmapped);
}

// One call for the dashboard landing page, scoped to the caller's organization.
router.get('/summary', async (request, response) => {
	try {
		const { orgID } = request.user;
		const [machines, applications, vulnerabilities, unmappedSoftware] = await Promise.all([machineCounts(orgID), applicationCount(orgID), vulnerabilityFigures(orgID), unmappedCount(orgID)]);
		return response.status(200).send({ message: 'Fleet summary retrieved.', machines, applications, vulnerabilities, unmappedSoftware });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to summarize the fleet.' });
	}
});

export default router;
