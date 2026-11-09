// Pure checks of NVD CVE configurations against a CPE name. No I/O.

const ANY = '*';
const VERSION_FIELD = 5;

const tokenize = version => version.toLowerCase().match(/\d+|[a-z]+/g) ?? [];

// Compare versions token by token: digit runs numerically, letter runs alphabetically; a version
// that is a prefix of the other is older (openssl 1.1.1 < 1.1.1m). Returns <0, 0 or >0.
export function compareVersions(left, right) {
	const leftTokens = tokenize(left);
	const rightTokens = tokenize(right);

	for (let index = 0; index < Math.min(leftTokens.length, rightTokens.length); index += 1) {
		const [a, b] = [leftTokens[index], rightTokens[index]];
		const bothNumeric = /^\d/.test(a) && /^\d/.test(b);
		const order = bothNumeric ? Number(a) - Number(b) : a.localeCompare(b);
		if (order !== 0) return Math.sign(order);
	}
	return Math.sign(leftTokens.length - rightTokens.length);
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

// True when any configuration node of the CVE has a vulnerable cpeMatch covering `cpeName`.
// NVD's cpeName filter also returns CVEs where the CPE is only a non-vulnerable platform.
export function cveAffectsCpe(cve, cpeName) {
	return (cve.configurations ?? []).some(configuration => (configuration.nodes ?? []).some(node => (node.cpeMatch ?? []).some(match => cpeMatchCovers(match, cpeName))));
}
