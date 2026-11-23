// Pure checks of NVD CVE configurations against a CPE name. No I/O.

const ANY = '*';
const VERSION_FIELD = 5;

const tokenize = version => version.toLowerCase().match(/\d+|[a-z]+/g) ?? [];

// Full words only: a single letter is an openssl patch release (1.1.1a), not a pre-release.
const isPreRelease = token => /^(?:alpha|beta|dev|pre|preview|rc)$/.test(token);

// Order of two tokens at the same position; `undefined` means that version has ended. An ended
// version equals a trailing zero part (Windows `12.3.2.0` is NVD's `12.3.2`).
function compareTokens(a, b) {
	if ((a === undefined && b === '0') || (a === '0' && b === undefined)) return 0;
	if (a === undefined) return isPreRelease(b) ? 1 : -1;
	if (b === undefined || isPreRelease(a) !== isPreRelease(b)) return isPreRelease(a) ? -1 : 1;
	const bothNumeric = /^\d/.test(a) && /^\d/.test(b);
	return Math.sign(bothNumeric ? Number(a) - Number(b) : a.localeCompare(b));
}

// Compare versions token by token: digit runs numerically, letter runs alphabetically; a version
// that is a prefix of the other is older (openssl 1.1.1 < 1.1.1m), unless the longer one goes on
// with a pre-release word (3.0.0-rc1 < 3.0.0). Returns <0, 0 or >0.
export function compareVersions(left, right) {
	const leftTokens = tokenize(left);
	const rightTokens = tokenize(right);

	for (let index = 0; index < Math.max(leftTokens.length, rightTokens.length); index += 1) {
		const order = compareTokens(leftTokens[index], rightTokens[index]);
		if (order !== 0) return order;
	}
	return 0;
}

// Every field but the version agrees (`*` on either side matches anything).
function otherFieldsMatch(criteria, target) {
	return criteria.every((field, index) => index < 2 || index === VERSION_FIELD || field === ANY || target[index] === ANY || field === target[index]);
}

function isWithinRange(version, { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding }) {
	if (versionStartIncluding && compareVersions(version, versionStartIncluding) < 0) return false;
	if (versionStartExcluding && compareVersions(version, versionStartExcluding) <= 0) return false;
	if (versionEndIncluding && compareVersions(version, versionEndIncluding) > 0) return false;
	if (versionEndExcluding && compareVersions(version, versionEndExcluding) >= 0) return false;
	return true;
}

// Does one NVD `cpeMatch` entry mark `cpeName` as vulnerable? A `*` version in the criteria defers
// to the optional version range bounds; a concrete one must equal the CPE's version.
export function cpeMatchCovers(match, cpeName) {
	if (match?.vulnerable !== true || typeof match.criteria !== 'string') return false;
	const criteria = match.criteria.split(':');
	const target = cpeName.split(':');
	if (criteria.length !== target.length || !otherFieldsMatch(criteria, target)) return false;

	const version = target[VERSION_FIELD];
	if (criteria[VERSION_FIELD] !== ANY) return criteria[VERSION_FIELD] === version;
	if (version === ANY || version === '-') return false;
	return isWithinRange(version, match);
}

const MAX_PLATFORMS = 20;
const TARGET_SW_FIELD = 10;

// target_sw values naming an operating system, as the OS criteria platform.js classifies.
const TARGET_OS_CRITERIA = new Map([
	['windows', 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*'],
	['linux', 'cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*'],
	['macos', 'cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*'],
	['mac_os_x', 'cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*'],
	['mac_os', 'cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*'],
	['iphone_os', 'cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*'],
	['ios', 'cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*'],
	['ipados', 'cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*'],
	['android', 'cpe:2.3:o:google:android:-:*:*:*:*:*:*:*']
]);

const coveringMatches = (node, cpeName) => (node.cpeMatch ?? []).filter(match => cpeMatchCovers(match, cpeName));

// The OS a vulnerable criterion is limited to through its target_sw field, as an OS criteria;
// undefined when it is not limited to a known OS (`*`, `-`, `node.js`...).
const targetOsCriteria = match => TARGET_OS_CRITERIA.get(match.criteria.split(':')[TARGET_SW_FIELD]);

// Under which platforms does the CVE apply to `cpeName`? undefined: it does not (no vulnerable
// match covers the CPE; NVD's cpeName filter also returns CVEs where the CPE is only a
// non-vulnerable platform). { platforms: [] }: whatever the platform. Otherwise the platforms that
// make it apply: the OS named by the covering criteria's own target_sw ("Teams for iPhone") when
// every covering criteria names one, else the platform criteria of the AND configurations
// ("vulnerable when running on Windows").
export function cveConditionsForCpe(cve, cpeName) {
	const platforms = new Set();
	let covered = false;

	for (const configuration of cve.configurations ?? []) {
		const nodes = configuration.nodes ?? [];
		const covering = nodes.flatMap(node => coveringMatches(node, cpeName));
		if (covering.length === 0) continue;
		covered = true;

		const targets = covering.map(match => targetOsCriteria(match));
		if (targets.every(Boolean)) {
			for (const criteria of targets) platforms.add(criteria);
			continue;
		}

		const required = configuration.operator === 'AND'
			? nodes.filter(node => coveringMatches(node, cpeName).length === 0).flatMap(node => (node.cpeMatch ?? []).filter(match => match.vulnerable === false).map(match => match.criteria))
			: [];
		if (required.length === 0) return { platforms: [] }; // one unconditional configuration wins
		for (const criteria of required) platforms.add(criteria);
	}
	return covered ? { platforms: [...platforms].slice(0, MAX_PLATFORMS) } : undefined;
}

// True when any configuration of the CVE has a vulnerable cpeMatch covering `cpeName`.
export function cveAffectsCpe(cve, cpeName) {
	return cveConditionsForCpe(cve, cpeName) !== undefined;
}
