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

// Store new records: a vulnerability row only when none exists (an NVD row keeps its data), and
// the id of each record (plus its non-CVE aliases) mapped to that row.
async function storeRecords(connection, records) {
	for (const record of records) {
		const id = storedID(record);
		const { cvssScore, severity } = scoreOf(record);
		await connection.query(`INSERT IGNORE INTO cve (cveID, description, cvssScore, severity, published, lastModified)
			VALUES (?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''))`,
		[id, record.summary || record.details?.slice(0, 2000) || '', cvssScore === undefined ? '' : String(cvssScore), severity ?? '', toSqlDateTime(record.published), toSqlDateTime(record.modified)]);
		const osvIDs = [record.id, ...(record.aliases ?? []).filter(alias => !alias.startsWith('CVE-'))];
		await connection.batch('INSERT IGNORE INTO osv_alias (osvID, cveID) VALUES (?, ?)', osvIDs.map(osvID => [osvID, id]));
	}
}

async function knownAliases(ids) {
	if (ids.length === 0) return new Map();
	const rows = await database.query('SELECT osvID, cveID FROM osv_alias WHERE osvID IN (?)', [ids]);
	return new Map(rows.map(({ osvID, cveID }) => [osvID, cveID]));
}

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

		const idsPerKey = await client.queryBatch(keys);
		const ids = [...new Set(idsPerKey.flat())];
		const known = await knownAliases(ids);
		const records = await fetchRecords(client, ids.filter(id => !known.has(id)));
		summary.fetched = records.length;
		for (const record of records) known.set(record.id, storedID(record));

		await database.transaction(async connection => {
			await storeRecords(connection, records);
			for (const [index, key] of keys.entries()) {
				const linked = [...new Set(idsPerKey[index].map(id => known.get(id)).filter(Boolean))];
				await connection.query('DELETE FROM package_vuln WHERE ecosystem = ? AND name = ? AND version = ?', [key.ecosystem, key.name, key.version]);
				if (linked.length > 0) await connection.batch('INSERT INTO package_vuln (ecosystem, name, version, cveID) VALUES (?, ?, ?, ?)', linked.map(cveID => [key.ecosystem, key.name, key.version, cveID]));
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
