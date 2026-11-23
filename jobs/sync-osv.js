import { getOsvClient, OsvError } from '../utils/osv.js';
import { cvssBaseScore, severityOfScore } from '../utils/cvss.js';
import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 2000;
const REFRESH_AFTER_HOURS = 24;
const PARALLEL_RECORDS = 8;
// GHSA bands as OSV reports them => the NVD severities stored in `cve`.
const BANDS = { LOW: 'LOW', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' };

const logger = baseLogger.child({ job: 'sync-osv' });
let running = false;

// OSV timestamps are RFC 3339 UTC (`2024-03-25T19:40:26Z`): DATETIME text, '' when absent.
const toSqlDateTime = value => (value ? new Date(value).toISOString().slice(0, 19).replace('T', ' ') : '');

// The row an OSV record is stored under: its CVE when it names exactly one, else its own id, so
// the advisories of one CVE (GHSA, PYSEC) and the NVD entry share a single vulnerability.
export function storedID(record) {
	const cves = (record.aliases ?? []).filter(alias => alias.startsWith('CVE-'));
	return cves.length === 1 ? cves[0] : record.id;
}

// Score from the first CVSS v3 vector; else the advisory's band without score.
export function scoreOf(record) {
	const vector = (record.severity ?? []).find(({ type }) => type === 'CVSS_V3')?.score;
	const cvssScore = vector ? cvssBaseScore(vector) : undefined;
	const severity = severityOfScore(cvssScore) ?? BANDS[String(record.database_specific?.severity).toUpperCase()];
	return { cvssScore, severity };
}

// Records of the ids not resolved yet, fetched a few at a time; ids OSV no longer knows are left out.
async function fetchRecords(client, ids) {
	const records = [];
	for (let start = 0; start < ids.length; start += PARALLEL_RECORDS) {
		records.push(...await Promise.all(ids.slice(start, start + PARALLEL_RECORDS).map(id => client.vuln(id))));
	}
	return records.filter(Boolean);
}

// Store fetched records: a new vulnerability row only when none exists (an NVD or Packagist row
// keeps its data); a refreshed record updates the row only when OSV created it. Each record id (plus
// its non-CVE aliases) is mapped to its row with the record's modification date.
async function storeRecords(connection, records, known) {
	for (const record of records) {
		const id = known.get(record.id)?.cveID ?? storedID(record);
		const { cvssScore, severity } = scoreOf(record);
		const values = [record.summary || record.details?.slice(0, 2000) || '', cvssScore === undefined ? '' : String(cvssScore), severity ?? '', toSqlDateTime(record.published), toSqlDateTime(record.modified)];
		await connection.query(`INSERT INTO cve (cveID, description, cvssScore, severity, published, lastModified, source)
			VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), 'osv')
			ON DUPLICATE KEY UPDATE
				description = IF(source = 'osv', VALUES(description), description), cvssScore = IF(source = 'osv', VALUES(cvssScore), cvssScore),
				severity = IF(source = 'osv', VALUES(severity), severity), published = IF(source = 'osv', VALUES(published), published),
				lastModified = IF(source = 'osv', VALUES(lastModified), lastModified)`, [id, ...values]);
		const osvIDs = [record.id, ...(record.aliases ?? []).filter(alias => !alias.startsWith('CVE-'))];
		await connection.batch(`INSERT INTO osv_alias (osvID, cveID, modified) VALUES (?, ?, NULLIF(?, ''))
			ON DUPLICATE KEY UPDATE modified = VALUES(modified)`, osvIDs.map(osvID => [osvID, id, toSqlDateTime(record.modified)]));
	}
}

// OSV ids already stored: their row and the modification date of the record stored.
async function knownAliases(ids) {
	if (ids.length === 0) return new Map();
	const rows = await database.query("SELECT osvID, cveID, DATE_FORMAT(modified, '%Y-%m-%dT%H:%i:%sZ') AS modified FROM osv_alias WHERE osvID IN (?)", [ids]);
	return new Map(rows.map(({ osvID, cveID, modified }) => [osvID, { cveID, modified }]));
}

// A known record is stale when OSV reports a later modification than the one stored (to the second).
const isStale = (stored, modified) => !stored.modified || Math.floor(Date.parse(modified) / 1000) > Date.parse(stored.modified) / 1000;

// One tick: query OSV for a bounded batch of package keys never checked or checked over 24 h ago.
// Every record is fetched before anything is written, so a failure leaves the keys pending as they were.
async function tick({ client = getOsvClient(), batchSize = BATCH_SIZE } = {}) {
	if (running) return { skipped: true };
	running = true;
	const summary = { checked: 0, linked: 0, fetched: 0, failed: 0 };

	try {
		const keys = await database.query(`SELECT ecosystem, name, version FROM package_vuln_key
			WHERE status = 'pending' OR checkedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? HOUR)
			ORDER BY status = 'checked', checkedAt LIMIT ?`, [REFRESH_AFTER_HOURS, batchSize]);
		if (keys.length === 0) return summary;

		const foundPerKey = await client.queryBatch(keys);
		const modifiedOf = new Map(foundPerKey.flat().map(({ id, modified }) => [id, modified]));
		const known = await knownAliases([...modifiedOf.keys()]);
		const due = [...modifiedOf].filter(([id, modified]) => !known.has(id) || isStale(known.get(id), modified)).map(([id]) => id);
		const records = await fetchRecords(client, due);
		summary.fetched = records.length;

		await database.transaction(async connection => {
			await storeRecords(connection, records, known);
			for (const record of records) if (!known.has(record.id)) known.set(record.id, { cveID: storedID(record) });
			for (const [index, key] of keys.entries()) {
				const linked = [...new Set(foundPerKey[index].map(({ id }) => known.get(id)?.cveID).filter(Boolean))];
				await connection.query("DELETE FROM package_vuln WHERE ecosystem = ? AND name = ? AND version = ? AND source = 'osv'", [key.ecosystem, key.name, key.version]);
				if (linked.length > 0) await connection.batch("INSERT INTO package_vuln (ecosystem, name, version, cveID, source) VALUES (?, ?, ?, ?, 'osv')", linked.map(cveID => [key.ecosystem, key.name, key.version, cveID]));
				await connection.query("UPDATE package_vuln_key SET status = 'checked', checkedAt = UTC_TIMESTAMP() WHERE ecosystem = ? AND name = ? AND version = ?", [key.ecosystem, key.name, key.version]);
				summary.linked += linked.length;
			}
		});
		summary.checked = keys.length;
	} catch (error) {
		summary.failed += 1;
		if (error instanceof OsvError) logger.warn(error, 'OSV unavailable, tick stopped early');
		else logger.error(error, 'OSV sync tick failed');
	} finally {
		running = false;
	}
	return summary;
}

// One tick on one API instance at a time (database lock), never overlapping itself in-process.
export function runOnce(options) {
	return withJobLock('sync-osv', () => tick(options));
}

export function startSyncOsvJob(intervalMs = 15 * 60_000) {
	const timer = setInterval(runOnce, intervalMs);
	timer.unref();
	return timer;
}
