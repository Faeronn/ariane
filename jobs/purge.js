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
// Then, in dependency order, what no machine references any more.
const ORPHAN_SOFTWARE_KEYS = `DELETE sc FROM software_cpe sc
	LEFT JOIN installed_software s ON s.vendor = sc.vendor AND s.name = sc.name AND s.version = sc.version
	WHERE s.softwareID IS NULL`;
const ORPHAN_CPE_LINKS = `DELETE cc FROM cpe_cve cc
	LEFT JOIN software_cpe sc ON sc.cpeName = cc.cpeName
	WHERE sc.softwareCpeID IS NULL`;
const ORPHAN_CVES = `DELETE c FROM cve c
	LEFT JOIN cpe_cve cc ON cc.cveID = c.cveID
	WHERE cc.cveID IS NULL`;

async function deleted(sql) {
	const result = await database.query(sql);
	return result.affectedRows;
}

async function deleteOldSnapshots(retentionDays) {
	let deleted = 0;
	for (;;) {
		const result = await database.query(OLD_SNAPSHOTS, [retentionDays, BATCH_SIZE]);
		deleted += result.affectedRows;
		if (result.affectedRows < BATCH_SIZE) return deleted;
	}
}

async function tick({ retentionDays = Number(process.env.SNAPSHOT_RETENTION_DAYS) || DEFAULT_RETENTION_DAYS } = {}) {
	const snapshots = await deleteOldSnapshots(retentionDays); // installed_software cascades
	const softwareKeys = await deleted(ORPHAN_SOFTWARE_KEYS);
	const cpeLinks = await deleted(ORPHAN_CPE_LINKS);
	const cves = await deleted(ORPHAN_CVES);
	const summary = { snapshots, softwareKeys, cpeLinks, cves };
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
