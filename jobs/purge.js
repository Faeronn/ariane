import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import baseLogger from '../utils/logger.js';

const DEFAULT_RETENTION_DAYS = 90;
const BATCH_SIZE = 1000;

const logger = baseLogger.child({ job: 'purge' });

// Snapshots received more than `retentionDays` ago, never a machine's latest one (its current state).
const OLD_SNAPSHOTS = `DELETE FROM inventory_snapshot WHERE snapshotID IN (
	SELECT snapshotID FROM (
		SELECT s.snapshotID FROM inventory_snapshot s
		WHERE s.receivedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
			AND s.snapshotID <> (SELECT MAX(latest.snapshotID) FROM inventory_snapshot latest WHERE latest.machineID = s.machineID)
		LIMIT ?
	) AS old
)`;
// Same rule for application snapshots: never an application's latest one.
const OLD_APPLICATION_SNAPSHOTS = `DELETE FROM application_snapshot WHERE snapshotID IN (
	SELECT snapshotID FROM (
		SELECT s.snapshotID FROM application_snapshot s
		WHERE s.receivedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)
			AND s.snapshotID <> (SELECT MAX(latest.snapshotID) FROM application_snapshot latest WHERE latest.applicationID = s.applicationID)
		LIMIT ?
	) AS old
)`;
// Then, in dependency order, what no machine or application references any more.
// A key stays while an installed program or a direct dependency still uses it.
const ORPHAN_SOFTWARE_KEYS = `DELETE sc FROM software_cpe sc
	LEFT JOIN installed_software s ON sc.ecosystem = '' AND s.vendor = sc.vendor AND s.name = sc.name AND s.version = sc.version
	WHERE s.softwareID IS NULL AND NOT EXISTS (
		SELECT 1 FROM application_dependency d
		WHERE d.direct = 1 AND d.ecosystem = sc.ecosystem AND d.name = sc.packageName AND d.version = sc.version
	)`;
const ORPHAN_CPE_LINKS = `DELETE cc FROM cpe_cve cc
	LEFT JOIN software_cpe sc ON sc.cpeName = cc.cpeName
	WHERE sc.softwareCpeID IS NULL`;
const ORPHAN_PACKAGE_KEYS = `DELETE k FROM package_vuln_key k
	LEFT JOIN application_dependency d ON d.ecosystem = k.ecosystem AND d.name = k.name AND d.version = k.version
	WHERE d.snapshotID IS NULL`;
const ORPHAN_PACKAGE_LINKS = `DELETE pv FROM package_vuln pv
	LEFT JOIN package_vuln_key k ON k.ecosystem = pv.ecosystem AND k.name = pv.name AND k.version = pv.version
	WHERE k.status IS NULL`;
// A vulnerability stays while a CPE or a package still links to it.
const ORPHAN_CVES = `DELETE c FROM cve c
	LEFT JOIN cpe_cve cc ON cc.cveID = c.cveID
	LEFT JOIN package_vuln pv ON pv.cveID = c.cveID
	WHERE cc.cveID IS NULL AND pv.cveID IS NULL`;

async function deleted(sql) {
	const result = await database.query(sql);
	return result.affectedRows;
}

async function deleteOldSnapshots(sql, retentionDays) {
	let deleted = 0;
	for (;;) {
		const result = await database.query(sql, [retentionDays, BATCH_SIZE]);
		deleted += result.affectedRows;
		if (result.affectedRows < BATCH_SIZE) return deleted;
	}
}

async function tick({ retentionDays = Number(process.env.SNAPSHOT_RETENTION_DAYS) || DEFAULT_RETENTION_DAYS } = {}) {
	const snapshots = await deleteOldSnapshots(OLD_SNAPSHOTS, retentionDays); // installed_software cascades
	const applicationSnapshots = await deleteOldSnapshots(OLD_APPLICATION_SNAPSHOTS, retentionDays); // application_dependency cascades
	const softwareKeys = await deleted(ORPHAN_SOFTWARE_KEYS);
	const cpeLinks = await deleted(ORPHAN_CPE_LINKS);
	const packageKeys = await deleted(ORPHAN_PACKAGE_KEYS);
	const packageLinks = await deleted(ORPHAN_PACKAGE_LINKS);
	const cves = await deleted(ORPHAN_CVES);
	const summary = { snapshots, applicationSnapshots, softwareKeys, cpeLinks, packageKeys, packageLinks, cves };
	logger.info(summary, 'Purge done');
	return summary;
}

// One purge on one API instance at a time.
export function runOnce(options) {
	return withJobLock('purge', () => tick(options));
}

export function startPurgeJob(intervalMs = 24 * 60 * 60_000) {
	const timer = setInterval(() => runOnce().catch(error => logger.error(error, 'Purge failed')), intervalMs);
	timer.unref();
	return timer;
}
