import { getPackagistClient, PackagistError } from '../utils/packagist.js';
import { satisfies } from '../utils/composer-constraint.js';
import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 2000;
const REFRESH_AFTER_HOURS = 24;
const BANDS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

const logger = baseLogger.child({ job: 'sync-packagist' });
let running = false;

// The row an advisory is stored under: its CVE, else its Packagist id (PKSA-...).
export const storedID = advisory => advisory.cve || advisory.advisoryId;

// Packagist dates are UTC `YYYY-MM-DD HH:MM:SS`, already DATETIME text.
const toSqlDateTime = value => (typeof value === 'string' && /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(value) ? value : '');

// Advisories of `advisories` affecting `version`; constraints the evaluator cannot read are
// skipped (never counted as affected) and logged.
function affecting(advisories, name, version) {
	return advisories.filter(advisory => {
		const verdict = satisfies(version, advisory.affectedVersions);
		if (verdict === undefined) logger.debug({ package: name, version, advisory: advisory.advisoryId, constraint: advisory.affectedVersions }, 'Constraint not evaluated');
		return verdict === true;
	});
}

async function store(connection, keys, advisoriesByName) {
	let linked = 0;
	for (const key of keys) {
		const hits = affecting(advisoriesByName[key.name] ?? [], key.name, key.version);
		for (const advisory of hits) {
			const severity = String(advisory.severity ?? '').toUpperCase();
			await connection.query(`INSERT IGNORE INTO cve (cveID, description, severity, published, source)
				VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), 'packagist')`,
			[storedID(advisory), advisory.title ?? '', BANDS.has(severity) ? severity : '', toSqlDateTime(advisory.reportedAt)]);
		}
		const ids = [...new Set(hits.map(advisory => storedID(advisory)))];
		await connection.query("DELETE FROM package_vuln WHERE ecosystem = ? AND name = ? AND version = ? AND source = 'packagist'", [key.ecosystem, key.name, key.version]);
		if (ids.length > 0) await connection.batch("INSERT INTO package_vuln (ecosystem, name, version, cveID, source) VALUES (?, ?, ?, ?, 'packagist')", ids.map(id => [key.ecosystem, key.name, key.version, id]));
		await connection.query('UPDATE package_vuln_key SET packagistCheckedAt = UTC_TIMESTAMP() WHERE ecosystem = ? AND name = ? AND version = ?', [key.ecosystem, key.name, key.version]);
		linked += ids.length;
	}
	return linked;
}

// One tick: the Packagist advisories of a bounded batch of Composer package keys never checked or
// checked over 24 h ago. One request per 100 package names; nothing is written before every answer
// is in, so a failure leaves the keys due as they were.
async function tick({ client = getPackagistClient(), batchSize = BATCH_SIZE } = {}) {
	if (running) return { skipped: true };
	running = true;
	const summary = { checked: 0, linked: 0, failed: 0 };

	try {
		const keys = await database.query(`SELECT ecosystem, name, version FROM package_vuln_key
			WHERE ecosystem = 'Packagist' AND (packagistCheckedAt IS NULL OR packagistCheckedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? HOUR))
			ORDER BY packagistCheckedAt IS NOT NULL, packagistCheckedAt LIMIT ?`, [REFRESH_AFTER_HOURS, batchSize]);
		if (keys.length === 0) return summary;

		const advisoriesByName = await client.advisories(keys.map(({ name }) => name));
		summary.linked = await database.transaction(connection => store(connection, keys, advisoriesByName));
		summary.checked = keys.length;
	} catch (error) {
		summary.failed += 1;
		if (error instanceof PackagistError) logger.warn(error, 'Packagist unavailable, tick stopped early');
		else logger.error(error, 'Packagist sync tick failed');
	} finally {
		running = false;
	}
	return summary;
}

// One tick on one API instance at a time (database lock), never overlapping itself in-process.
export function runOnce(options) {
	return withJobLock('sync-packagist', () => tick(options));
}

export function startSyncPackagistJob(intervalMs = 15 * 60_000) {
	const timer = setInterval(runOnce, intervalMs);
	timer.unref();
	return timer;
}
