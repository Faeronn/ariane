import { getNvdClient, NvdError } from '../utils/nvd.js';
import database from '../utils/database.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 20;
const RETRY_UNMATCHED_AFTER_DAYS = 7;
const RELEASE_UPDATES = new Set(['*', '-']);

const logger = baseLogger.child({ job: 'resolve-cpe' });
let running = false;

// CPE 2.3 formatted string => its fields (`cpe:2.3:part:vendor:product:version:update:...`).
function parseCpe(cpeName) {
	const fields = cpeName.split(':');
	return { part: fields[2], vendor: fields[3], product: fields[4], version: fields[5], update: fields[6] };
}

// Software names use spaces, CPE products use underscores.
const toCpeToken = value => value.trim().toLowerCase().replaceAll(/\s+/g, '_');

// Distribution package version => upstream version: drop the epoch (`1:`), the packaging revision
// after the last hyphen when it starts with a digit (Debian `-1~deb12u2`, Ubuntu `-0ubuntu1.4`,
// RPM `-27.el9`) and a repack suffix (`+dfsg`). `3.0.0-beta1` stays as is.
export function upstreamVersion(version) {
	return version.replace(/^\d+:/, '').replace(/-\d[^-]*$/, '').replace(/\+(?:dfsg|ds)\d*$/, '');
}

// Pick the CPE of `software` among NVD search results: same product and exact version, a release
// (no alpha/beta update), vendor matching when the inventory gave one, deprecated names replaced
// by their successor. Returns the cpeName only when exactly one remains, else undefined.
export function pickCpe(software, products) {
	const product = toCpeToken(software.name);
	const vendor = software.vendor ? toCpeToken(software.vendor) : undefined;

	const candidates = products.map(({ cpe }) => cpe).filter(cpe => {
		const fields = parseCpe(cpe.cpeName);
		return fields.part === 'a' && fields.product === product && fields.version === software.version && RELEASE_UPDATES.has(fields.update);
	});
	const sameVendor = vendor ? candidates.filter(cpe => parseCpe(cpe.cpeName).vendor === vendor) : candidates;
	const resolved = new Set((sameVendor.length > 0 ? sameVendor : candidates).map(cpe => {
		if (!cpe.deprecated) return cpe.cpeName;
		return cpe.deprecatedBy?.length === 1 ? cpe.deprecatedBy[0].cpeName : undefined;
	}).filter(Boolean));

	return resolved.size === 1 ? [...resolved][0] : undefined;
}

// One tick: resolve a bounded batch of pending keys and stale unmatched ones. Never overlaps itself;
// an NVD failure ends the tick early and leaves the remaining keys for the next one.
export async function runOnce({ client = getNvdClient(), batchSize = BATCH_SIZE } = {}) {
	if (running) return { skipped: true };
	running = true;
	const summary = { matched: 0, unmatched: 0, failed: 0 };

	try {
		const keys = await database.query(`SELECT softwareCpeID, vendor, name, version FROM software_cpe
			WHERE status = 'pending' OR (status = 'unmatched' AND lastCheckedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))
			ORDER BY lastCheckedAt IS NOT NULL, lastCheckedAt, softwareCpeID LIMIT ?`, [RETRY_UNMATCHED_AFTER_DAYS, batchSize]);

		for (const key of keys) {
			// A packaged version is matched on its upstream one; distributions often backport fixes
			// without changing it, so such matches are flagged for review rather than trusted.
			const version = upstreamVersion(key.version);
			const products = version ? await client.searchCpes(`${key.name} ${version}`) : [];
			const cpeName = pickCpe({ ...key, version }, products);
			await database.query(`UPDATE software_cpe SET cpeName = NULLIF(?, ''), versionNormalized = ?, status = ?, lastCheckedAt = UTC_TIMESTAMP() WHERE softwareCpeID = ?`, [cpeName ?? '', version !== key.version, cpeName ? 'matched' : 'unmatched', key.softwareCpeID]);
			summary[cpeName ? 'matched' : 'unmatched'] += 1;
		}
	} catch (error) {
		summary.failed += 1;
		if (error instanceof NvdError) logger.warn(error, 'NVD unavailable, tick stopped early');
		else logger.error(error, 'CPE resolution tick failed');
	} finally {
		running = false;
	}
	return summary;
}

export function startResolveCpeJob(intervalMs = 5 * 60_000) {
	const timer = setInterval(runOnce, intervalMs);
	timer.unref();
	return timer;
}
