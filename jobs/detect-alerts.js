import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import { programVulnerabilities, applicationVulnerabilities } from '../utils/vulnerabilities.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 50;
const logger = baseLogger.child({ job: 'detect-alerts' });

// Compare an item's current CVEs with its recorded state: open new ones (unsent, or already marked
// sent during the item's baseline), resolve the ones gone, reopen the ones back. An item is a
// machine (its installed programs) or an application (its packages).
async function detectItem(connection, itemType, itemID, vulnerabilities, baseline) {
	const current = new Set(vulnerabilities.map(({ cveID }) => cveID));
	const state = await connection.query('SELECT cveID, resolvedAt FROM item_cve_state WHERE itemType = ? AND itemID = ? FOR UPDATE', [itemType, itemID]);
	const known = new Map(state.map(({ cveID, resolvedAt }) => [cveID, resolvedAt]));
	const stamp = baseline ? 'UTC_TIMESTAMP()' : 'NULL';

	const opened = [...current].filter(cveID => !known.has(cveID));
	const reopened = [...current].filter(cveID => known.has(cveID) && known.get(cveID));
	const resolved = [...known].filter(([cveID, resolvedAt]) => !resolvedAt && !current.has(cveID)).map(([cveID]) => cveID);

	if (opened.length > 0) await connection.batch(`INSERT INTO item_cve_state (itemType, itemID, cveID, firstSeenAt, emailSentAt, webhookSentAt) VALUES (?, ?, ?, UTC_TIMESTAMP(), ${stamp}, ${stamp})`, opened.map(cveID => [itemType, itemID, cveID]));
	if (reopened.length > 0) await connection.batch(`UPDATE item_cve_state SET resolvedAt = NULL, firstSeenAt = UTC_TIMESTAMP(), emailSentAt = ${stamp}, webhookSentAt = ${stamp} WHERE itemType = ? AND itemID = ? AND cveID = ?`, reopened.map(cveID => [itemType, itemID, cveID]));
	if (resolved.length > 0) await connection.batch('UPDATE item_cve_state SET resolvedAt = UTC_TIMESTAMP() WHERE itemType = ? AND itemID = ? AND cveID = ?', resolved.map(cveID => [itemType, itemID, cveID]));
	return { opened: opened.length + reopened.length, resolved: resolved.length };
}

const UNSYNCED_KEY = "(sc.status = 'pending' OR (sc.status = 'matched' AND sc.cvesCheckedAt IS NULL))";

// Programs of the machine's latest snapshot still waiting for their CPE or that CPE's CVEs.
async function unresolvedPrograms(machineID) {
	const [{ unresolved }] = await database.query(`SELECT COUNT(*) AS unresolved FROM installed_software s
		INNER JOIN software_cpe sc ON sc.ecosystem = '' AND sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
		WHERE s.snapshotID = (SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = ?) AND ${UNSYNCED_KEY}`, [machineID]);
	return Number(unresolved);
}

// Packages of the application's latest snapshot still waiting for OSV, Packagist (Composer) or,
// for direct ones, the NVD.
async function unresolvedPackages(applicationID) {
	const latest = 'd.snapshotID = (SELECT MAX(snapshotID) FROM application_snapshot WHERE applicationID = ?)';
	const [{ unresolved }] = await database.query(`SELECT
		(SELECT COUNT(*) FROM application_dependency d
			INNER JOIN package_vuln_key k ON k.ecosystem = d.ecosystem AND k.name = d.name AND k.version = d.version
			WHERE ${latest} AND (k.status = 'pending' OR (k.ecosystem = 'Packagist' AND k.packagistCheckedAt IS NULL)))
		+ (SELECT COUNT(*) FROM application_dependency d
			INNER JOIN software_cpe sc ON d.direct = 1 AND sc.ecosystem = d.ecosystem AND sc.packageName = d.name AND sc.version = d.version
			WHERE ${latest} AND ${UNSYNCED_KEY}) AS unresolved`, [applicationID, applicationID]);
	return Number(unresolved);
}

const ITEM_TABLES = { machine: { table: 'machines', idColumn: 'machineID' }, application: { table: 'applications', idColumn: 'applicationID' } };

// One item through detection: deferred while its first state (baseline) would be incomplete, else
// compared with its state; its baseline and check dates are recorded on the item's row.
async function processItem(summary, { itemType, itemID, baseline, unresolved, vulnerabilities }) {
	// The baseline must hold the item's complete first state: CVEs found later for software already
	// there would otherwise be alerted as new. Not yet checked, the item is retried first.
	if (baseline && await unresolved() > 0) {
		summary.deferred += 1;
		return;
	}
	const current = await vulnerabilities();
	const { table, idColumn } = ITEM_TABLES[itemType];
	const { opened, resolved } = await database.transaction(async connection => {
		const counts = await detectItem(connection, itemType, itemID, current, baseline);
		await connection.query(`UPDATE ${table} SET alertsBaselineAt = COALESCE(alertsBaselineAt, UTC_TIMESTAMP()), alertsCheckedAt = UTC_TIMESTAMP() WHERE ${idColumn} = ?`, [itemID]);
		return counts;
	});
	summary.items += 1;
	summary.opened += opened;
	summary.resolved += resolved;
}

// Each active machine, then each of its applications, as separate items.
async function tick({ batchSize = BATCH_SIZE } = {}) {
	const machines = await database.query(`SELECT machineID, alertsBaselineAt FROM machines WHERE revokedAt IS NULL
		ORDER BY alertsCheckedAt IS NOT NULL, alertsCheckedAt, machineID LIMIT ?`, [batchSize]);
	const summary = { items: 0, opened: 0, resolved: 0, deferred: 0 };
	for (const machine of machines) {
		await processItem(summary, {
			itemType: 'machine', itemID: machine.machineID, baseline: !machine.alertsBaselineAt,
			unresolved: () => unresolvedPrograms(machine.machineID), vulnerabilities: () => programVulnerabilities(machine.machineID)
		});
		const applications = await database.query('SELECT applicationID, alertsBaselineAt FROM applications WHERE machineID = ? ORDER BY applicationID', [machine.machineID]);
		for (const application of applications) {
			await processItem(summary, {
				itemType: 'application', itemID: application.applicationID, baseline: !application.alertsBaselineAt,
				unresolved: () => unresolvedPackages(application.applicationID), vulnerabilities: () => applicationVulnerabilities(application.applicationID)
			});
		}
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
