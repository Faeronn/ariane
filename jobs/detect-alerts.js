import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import { machineVulnerabilities } from '../utils/vulnerabilities.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 50;
const logger = baseLogger.child({ job: 'detect-alerts' });

// Applications of the machine registered since its last detection: their first state is a baseline
// too, so registering an application on a monitored machine does not alert its existing findings.
const newApplications = machineID => database.query('SELECT applicationID, name FROM applications WHERE machineID = ? AND alertsBaselineAt IS NULL', [machineID]);

// Compare a machine's current CVEs with its recorded state: open new ones (unsent, or already
// marked sent when they belong to a baseline: the machine's first run, or only to applications
// seen for the first time), resolve the ones gone, reopen the ones back.
async function detectMachine({ machineID, alertsBaselineAt }, applications) {
	const vulnerabilities = await machineVulnerabilities(machineID);
	const current = new Set(vulnerabilities.map(({ cveID }) => cveID));
	const firstSeen = new Set(applications.map(({ name }) => name));
	const baseline = new Set(vulnerabilities
		.filter(({ software }) => !alertsBaselineAt || software.every(({ application }) => firstSeen.has(application)))
		.map(({ cveID }) => cveID));

	return database.transaction(async connection => {
		const state = await connection.query('SELECT cveID, resolvedAt FROM machine_cve_state WHERE machineID = ? FOR UPDATE', [machineID]);
		const known = new Map(state.map(({ cveID, resolvedAt }) => [cveID, resolvedAt]));

		const opened = [...current].filter(cveID => !known.has(cveID));
		const reopened = [...current].filter(cveID => known.has(cveID) && known.get(cveID));
		const resolved = [...known].filter(([cveID, resolvedAt]) => !resolvedAt && !current.has(cveID)).map(([cveID]) => cveID);

		for (const sent of [true, false]) {
			const openedNow = opened.filter(cveID => baseline.has(cveID) === sent);
			const reopenedNow = reopened.filter(cveID => baseline.has(cveID) === sent);
			const stamp = sent ? 'UTC_TIMESTAMP()' : 'NULL';
			if (openedNow.length > 0) await connection.batch(`INSERT INTO machine_cve_state (machineID, cveID, firstSeenAt, emailSentAt, webhookSentAt) VALUES (?, ?, UTC_TIMESTAMP(), ${stamp}, ${stamp})`, openedNow.map(cveID => [machineID, cveID]));
			if (reopenedNow.length > 0) await connection.batch(`UPDATE machine_cve_state SET resolvedAt = NULL, firstSeenAt = UTC_TIMESTAMP(), emailSentAt = ${stamp}, webhookSentAt = ${stamp} WHERE machineID = ? AND cveID = ?`, reopenedNow.map(cveID => [machineID, cveID]));
		}
		if (resolved.length > 0) await connection.batch('UPDATE machine_cve_state SET resolvedAt = UTC_TIMESTAMP() WHERE machineID = ? AND cveID = ?', resolved.map(cveID => [machineID, cveID]));
		await connection.query('UPDATE machines SET alertsBaselineAt = COALESCE(alertsBaselineAt, UTC_TIMESTAMP()), alertsCheckedAt = UTC_TIMESTAMP() WHERE machineID = ?', [machineID]);
		if (applications.length > 0) await connection.query('UPDATE applications SET alertsBaselineAt = UTC_TIMESTAMP() WHERE applicationID IN (?)', [applications.map(({ applicationID }) => applicationID)]);

		return { opened: opened.length + reopened.length, resolved: resolved.length };
	});
}

const UNSYNCED_KEY = "(sc.status = 'pending' OR (sc.status = 'matched' AND sc.cvesCheckedAt IS NULL))";
const LATEST_DEPENDENCIES = `FROM applications a
	INNER JOIN application_snapshot s ON s.applicationID = a.applicationID
		AND s.snapshotID = (SELECT MAX(latest.snapshotID) FROM application_snapshot latest WHERE latest.applicationID = a.applicationID)
	INNER JOIN application_dependency d ON d.snapshotID = s.snapshotID`;

// Software of the machine's latest snapshot still waiting for its CPE or for that CPE's CVEs, and
// dependencies of its applications still waiting for OSV or (direct ones) for the NVD.
async function countUnresolved(machineID) {
	const [{ unresolved }] = await database.query(`SELECT
		(SELECT COUNT(*) FROM installed_software s
			INNER JOIN software_cpe sc ON sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
			WHERE s.snapshotID = (SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = ?) AND ${UNSYNCED_KEY})
		+ (SELECT COUNT(*) ${LATEST_DEPENDENCIES}
			INNER JOIN package_vuln_key k ON k.ecosystem = d.ecosystem AND k.name = d.name AND k.version = d.version
			WHERE a.machineID = ? AND k.status = 'pending')
		+ (SELECT COUNT(*) ${LATEST_DEPENDENCIES}
			INNER JOIN software_cpe sc ON d.direct = 1 AND sc.ecosystem = d.ecosystem AND sc.packageName = d.name AND sc.version = d.version
			WHERE a.machineID = ? AND ${UNSYNCED_KEY}) AS unresolved`, [machineID, machineID, machineID]);
	return Number(unresolved);
}

async function tick({ batchSize = BATCH_SIZE } = {}) {
	const machines = await database.query(`SELECT machineID, alertsBaselineAt FROM machines WHERE revokedAt IS NULL
		ORDER BY alertsCheckedAt IS NOT NULL, alertsCheckedAt, machineID LIMIT ?`, [batchSize]);
	const summary = { machines: 0, opened: 0, resolved: 0, deferred: 0 };
	for (const machine of machines) {
		// A baseline (the machine's, or a new application's) must hold the complete first state: CVEs
		// found later for software already there would otherwise be alerted as new. Not yet checked,
		// the machine is retried first.
		const applications = await newApplications(machine.machineID);
		if ((!machine.alertsBaselineAt || applications.length > 0) && await countUnresolved(machine.machineID) > 0) {
			summary.deferred += 1;
			continue;
		}
		const { opened, resolved } = await detectMachine(machine, applications);
		summary.machines += 1;
		summary.opened += opened;
		summary.resolved += resolved;
	}
	return summary;
}

// One detection pass on one API instance at a time.
export function runOnce(options) {
	return withJobLock('detect-alerts', () => tick(options));
}

export function startDetectAlertsJob(intervalMs = 15 * 60_000) {
	const timer = setInterval(() => runOnce().catch(error => logger.error(error, 'Alert detection failed')), intervalMs);
	timer.unref();
	return timer;
}
