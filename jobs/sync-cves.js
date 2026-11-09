import { getNvdClient, NvdError } from '../utils/nvd.js';
import { cveAffectsCpe } from '../utils/cpe-match.js';
import database from '../utils/database.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 10;
const REFRESH_AFTER_HOURS = 24;
const SCORE_SOURCES = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];

const logger = baseLogger.child({ job: 'sync-cves' });
let running = false;

// CVSS score and severity, preferring v3.1, then v3.0, then v2 (Primary source first).
export function pickScore(metrics = {}) {
	for (const source of SCORE_SOURCES) {
		const entries = metrics[source] ?? [];
		const metric = entries.find(entry => entry.type === 'Primary') ?? entries[0];
		if (metric?.cvssData) return { cvssScore: metric.cvssData.baseScore, severity: metric.cvssData.baseSeverity ?? metric.baseSeverity };
	}
	return { cvssScore: undefined, severity: undefined };
}

// Missing values travel as '' and become NULL through NULLIF in SQL.
// NVD timestamps are UTC without a zone (`2022-03-15T17:15:08.433`).
const toSqlDateTime = value => (value ? value.slice(0, 19).replace('T', ' ') : '');

// One tick: refresh the CVE links of a bounded batch of matched CPEs never synced or older than 24 h.
// Each CPE's links are replaced atomically, so CVEs NVD no longer reports disappear.
export async function runOnce({ client = getNvdClient(), batchSize = BATCH_SIZE } = {}) {
	if (running) return { skipped: true };
	running = true;
	const summary = { synced: 0, linked: 0, failed: 0 };

	try {
		const cpes = await database.query(`SELECT cpeName FROM software_cpe
			WHERE status = 'matched' AND (cvesCheckedAt IS NULL OR cvesCheckedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? HOUR))
			GROUP BY cpeName ORDER BY MIN(cvesCheckedAt IS NOT NULL), MIN(cvesCheckedAt) LIMIT ?`, [REFRESH_AFTER_HOURS, batchSize]);

		for (const { cpeName } of cpes) {
			const vulnerabilities = await client.getCvesByCpe(cpeName);
			const cves = vulnerabilities.map(({ cve }) => cve).filter(cve => cveAffectsCpe(cve, cpeName));
			await storeLinks(cpeName, cves);
			summary.synced += 1;
			summary.linked += cves.length;
		}
	} catch (error) {
		summary.failed += 1;
		if (error instanceof NvdError) logger.warn(error, 'NVD unavailable, tick stopped early');
		else logger.error(error, 'CVE sync tick failed');
	} finally {
		running = false;
	}
	return summary;
}

function storeLinks(cpeName, cves) {
	return database.transaction(async connection => {
		if (cves.length > 0) {
			await connection.batch(`INSERT INTO cve (cveID, description, cvssScore, severity, published, lastModified) VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''), NULLIF(?, ''))
				ON DUPLICATE KEY UPDATE description = VALUES(description), cvssScore = VALUES(cvssScore), severity = VALUES(severity), published = VALUES(published), lastModified = VALUES(lastModified)`,
			cves.map(cve => {
				const { cvssScore, severity } = pickScore(cve.metrics);
				const description = cve.descriptions?.find(entry => entry.lang === 'en')?.value ?? '';
				return [cve.id, description, cvssScore === undefined ? '' : String(cvssScore), severity ?? '', toSqlDateTime(cve.published), toSqlDateTime(cve.lastModified)];
			}));
		}
		await connection.query('DELETE FROM cpe_cve WHERE cpeName = ?', [cpeName]);
		if (cves.length > 0) await connection.batch('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', cves.map(cve => [cpeName, cve.id]));
		await connection.query('UPDATE software_cpe SET cvesCheckedAt = UTC_TIMESTAMP() WHERE cpeName = ?', [cpeName]);
	});
}

export function startSyncCvesJob(intervalMs = 15 * 60_000) {
	const timer = setInterval(runOnce, intervalMs);
	timer.unref();
	return timer;
}
