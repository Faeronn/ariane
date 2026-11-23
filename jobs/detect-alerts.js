import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import { machineVulnerabilities } from '../utils/vulnerabilities.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 50;
const logger = baseLogger.child({ job: 'detect-alerts' });

// Compare a machine's current CVEs with its recorded state: open new ones (unsent, or already
// marked sent during the machine's baseline run), resolve the ones gone, reopen the ones back.
async function detectMachine({ machineID, alertsBaselineAt }) {
	const vulnerabilities = await machineVulnerabilities(machineID);
	const current = new Set(vulnerabilities.map(({ cveID }) => cveID));
	const baseline = !alertsBaselineAt;

	return database.transaction(async connection => {
		const state = await connection.query('SELECT cveID, resolvedAt FROM machine_cve_state WHERE machineID = ? FOR UPDATE', [machineID]);
		const known = new Map(state.map(({ cveID, resolvedAt }) => [cveID, resolvedAt]));
		const sentAt = baseline ? 'UTC_TIMESTAMP()' : 'NULL';

		const opened = [...current].filter(cveID => !known.has(cveID));
		const reopened = [...current].filter(cveID => known.has(cveID) && known.get(cveID));
		const resolved = [...known].filter(([cveID, resolvedAt]) => !resolvedAt && !current.has(cveID)).map(([cveID]) => cveID);

		if (opened.length > 0) await connection.batch(`INSERT INTO machine_cve_state (machineID, cveID, firstSeenAt, emailSentAt, webhookSentAt) VALUES (?, ?, UTC_TIMESTAMP(), ${sentAt}, ${sentAt})`, opened.map(cveID => [machineID, cveID]));
		if (reopened.length > 0) await connection.batch(`UPDATE machine_cve_state SET resolvedAt = NULL, firstSeenAt = UTC_TIMESTAMP(), emailSentAt = ${sentAt}, webhookSentAt = ${sentAt} WHERE machineID = ? AND cveID = ?`, reopened.map(cveID => [machineID, cveID]));
		if (resolved.length > 0) await connection.batch('UPDATE machine_cve_state SET resolvedAt = UTC_TIMESTAMP() WHERE machineID = ? AND cveID = ?', resolved.map(cveID => [machineID, cveID]));
		await connection.query('UPDATE machines SET alertsBaselineAt = COALESCE(alertsBaselineAt, UTC_TIMESTAMP()), alertsCheckedAt = UTC_TIMESTAMP() WHERE machineID = ?', [machineID]);

		return { opened: opened.length + reopened.length, resolved: resolved.length };
	});
}

// Software of the machine's latest snapshot still waiting for its CPE or for that CPE's CVEs.
async function countUnresolved(machineID) {
	const [{ unresolved }] = await database.query(`SELECT COUNT(*) AS unresolved
		FROM installed_software s
		INNER JOIN software_cpe sc ON sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
		WHERE s.snapshotID = (SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = ?)
			AND (sc.status = 'pending' OR (sc.status = 'matched' AND sc.cvesCheckedAt IS NULL))`, [machineID]);
	return Number(unresolved);
}

async function tick({ batchSize = BATCH_SIZE } = {}) {
	const machines = await database.query(`SELECT machineID, alertsBaselineAt FROM machines WHERE revokedAt IS NULL
		ORDER BY alertsCheckedAt IS NOT NULL, alertsCheckedAt, machineID LIMIT ?`, [batchSize]);
	const summary = { machines: 0, opened: 0, resolved: 0, deferred: 0 };
	for (const machine of machines) {
		// The baseline must hold the machine's complete first state: CVEs found later for software
		// already there would otherwise be alerted as new. Not yet checked, it is retried first.
		if (!machine.alertsBaselineAt && await countUnresolved(machine.machineID) > 0) {
			summary.deferred += 1;
			continue;
		}
		const { opened, resolved } = await detectMachine(machine);
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
