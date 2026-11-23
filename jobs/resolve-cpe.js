import { getNvdClient, NvdError } from '../utils/nvd.js';
import { productCandidates } from '../utils/software-name.js';
import { ECOSYSTEM_TARGETS } from '../utils/package-key.js';
import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import baseLogger from '../utils/logger.js';

const BATCH_SIZE = 20;
const RETRY_UNMATCHED_AFTER_DAYS = 7;
const RELEASE_UPDATES = new Set(['*', '-']);

const logger = baseLogger.child({ job: 'resolve-cpe' });
let running = false;

// CPE 2.3 formatted string => its fields (`cpe:2.3:part:vendor:product:version:update:...`).
function parseCpe(cpeName) {
	const fields = cpeName.split(':');
	return { part: fields[2], vendor: fields[3], product: fields[4], version: fields[5], update: fields[6], targetSoftware: fields[10] };
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
// by their successor. A package of an ecosystem only takes a CPE made for it (target_sw `node.js`
// for npm...) or for any platform, which keeps homonyms out. Returns the cpeName only when exactly
// one remains, else undefined.
export function pickCpe(software, products) {
	const product = toCpeToken(software.name);
	const vendor = software.vendor ? toCpeToken(software.vendor) : undefined;
	const targets = software.ecosystem ? new Set(['*', '-', ECOSYSTEM_TARGETS[software.ecosystem]]) : undefined;

	const candidates = products.map(({ cpe }) => cpe).filter(cpe => {
		const fields = parseCpe(cpe.cpeName);
		if (targets && !targets.has(fields.targetSoftware)) return false;
		return fields.part === 'a' && fields.product === product && fields.version === software.version && RELEASE_UPDATES.has(fields.update);
	});
	const sameVendor = vendor ? candidates.filter(cpe => parseCpe(cpe.cpeName).vendor === vendor) : candidates;
	// A package scope or Composer vendor names the publisher: `@types/ws` is not `ws_project:ws`.
	// An installed program's vendor is free text, so it only breaks ties.
	const strictVendor = Boolean(software.ecosystem && vendor);
	const resolved = new Set((sameVendor.length > 0 || strictVendor ? sameVendor : candidates).map(cpe => {
		if (!cpe.deprecated) return cpe.cpeName;
		return cpe.deprecatedBy?.length === 1 ? cpe.deprecatedBy[0].cpeName : undefined;
	}).filter(Boolean));

	return resolved.size === 1 ? [...resolved][0] : undefined;
}

// Most specific alias whose patterns match the lowercased name (and vendor when the alias has one).
async function findAlias({ name, vendor }) {
	const [alias] = await database.query(`SELECT cpePart, cpeVendor, cpeProduct, versionParts FROM software_alias
		WHERE ? LIKE namePattern AND (vendorPattern IS NULL OR ? LIKE vendorPattern)
		ORDER BY CHAR_LENGTH(namePattern) DESC, vendorPattern IS NULL LIMIT 1`, [name, vendor]);
	return alias;
}

// First `parts` dot-separated parts of a version (Windows build `8.0.21.35325`, 3 => `8.0.21`);
// all of it when `parts` is not set.
export function keepVersionParts(version, parts) {
	return parts ? version.split('.').slice(0, parts).join('.') : version;
}

// Versions safe to place unescaped in a CPE 2.3 formatted string.
const SYNTHETIC_VERSION = /^[\w.-]+$/;

// Known product: ask the CPE dictionary for exactly this vendor, product and version. When the
// dictionary lacks the version but knows the product, build the CPE name ourselves (synthetic),
// unless `allowSynthetic` is false.
async function resolveByAlias(client, software, alias, { allowSynthetic }) {
	const product = `cpe:2.3:${alias.cpePart}:${alias.cpeVendor}:${alias.cpeProduct}`;
	const version = keepVersionParts(software.version, alias.versionParts);
	const products = await client.searchCpesByMatchString(`${product}:${version}`);
	const cpeName = pickCpe({ name: alias.cpeProduct, vendor: alias.cpeVendor, version }, products);
	if (cpeName) return { cpeName, synthetic: false };
	if (!allowSynthetic || !SYNTHETIC_VERSION.test(version) || !(await client.cpeExists(product))) return {};
	return { cpeName: `${product}:${version}:*:*:*:*:*:*:*`, synthetic: true };
}

// Try each product candidate of the display name ("Mozilla Firefox (x64 fr)" => firefox, ...)
// until one resolves; at most one NVD keyword search per candidate. Resolves to undefined when none does.
async function resolveByKeyword(client, software) {
	for (const product of productCandidates(software)) {
		const products = await client.searchCpes(`${product.replaceAll('_', ' ')} ${software.version}`);
		const cpeName = pickCpe({ ...software, name: product }, products);
		if (cpeName) return cpeName;
	}
}

// An alias, when one matches, decides alone; otherwise the name candidates are searched.
async function resolve(client, software, options) {
	const alias = await findAlias(software);
	if (alias) return resolveByAlias(client, software, alias, options);
	return { cpeName: await resolveByKeyword(client, software), synthetic: false };
}

// The version as reported first: the dictionary decides whether a hyphen suffix belongs to the
// upstream version (ImageMagick `7.1.2-30`). Only when nothing matches, the upstream version of a
// distribution package (`3.0.11-1~deb12u2` => `3.0.11`); distributions often backport fixes
// without changing it, so such matches are flagged `versionNormalized` for review. A synthetic CPE
// is never built on a version that still carries a packaging revision.
async function resolveKey(client, key) {
	// A package version is exact and its name is no display name: no alias, no upstream fallback.
	if (key.ecosystem) return { cpeName: await resolveByKeyword(client, key), synthetic: false, versionNormalized: false };
	const upstream = upstreamVersion(key.version);
	if (!upstream) return {};
	const packaged = upstream !== key.version;
	const exact = await resolve(client, key, { allowSynthetic: !packaged });
	if (exact.cpeName || !packaged) return { ...exact, versionNormalized: false };
	const normalized = await resolve(client, { ...key, version: upstream }, { allowSynthetic: true });
	return { ...normalized, versionNormalized: Boolean(normalized.cpeName) };
}

// One tick: resolve a bounded batch of pending keys and stale unmatched ones. Never overlaps itself;
// an NVD failure ends the tick early and leaves the remaining keys for the next one.
async function tick({ client = getNvdClient(), batchSize = BATCH_SIZE } = {}) {
	if (running) return { skipped: true };
	running = true;
	const summary = { matched: 0, unmatched: 0, failed: 0 };

	try {
		const keys = await database.query(`SELECT softwareCpeID, vendor, name, version, ecosystem FROM software_cpe
			WHERE status = 'pending' OR (status = 'unmatched' AND lastCheckedAt < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))
			ORDER BY lastCheckedAt IS NOT NULL, lastCheckedAt, softwareCpeID LIMIT ?`, [RETRY_UNMATCHED_AFTER_DAYS, batchSize]);

		for (const key of keys) {
			const { cpeName, synthetic = false, versionNormalized = false } = await resolveKey(client, key);
			await database.query(`UPDATE software_cpe SET cpeName = NULLIF(?, ''), cpeSynthetic = ?, versionNormalized = ?, status = ?, lastCheckedAt = UTC_TIMESTAMP() WHERE softwareCpeID = ?`, [cpeName ?? '', synthetic, versionNormalized, cpeName ? 'matched' : 'unmatched', key.softwareCpeID]);
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

// One tick on one API instance at a time (database lock), never overlapping itself in-process.
export function runOnce(options) {
	return withJobLock('resolve-cpe', () => tick(options));
}

export function startResolveCpeJob(intervalMs = 5 * 60_000) {
	const timer = setInterval(runOnce, intervalMs);
	timer.unref();
	return timer;
}
