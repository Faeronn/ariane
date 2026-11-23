import { vulnerabilityLink } from './vulnerability-link.js';

// The channel-neutral description of an alert for one item: what is new on a machine's programs or
// on one application's packages, grouped by software. Email and chat layouts render it.

export const MAX_LISTED = 100;
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

// Severity order, unscored last: an unscored CVE is reported, but after the scored ones.
const rankOf = severity => RANK[severity] ?? 0;
const byGravity = (left, right) => rankOf(right.severity) - rankOf(left.severity) || (right.score ?? -1) - (left.score ?? -1) || left.id.localeCompare(right.id);
// The highest severity among the entries; undefined when none is scored.
function worstOf(vulnerabilities) {
	let worst;
	for (const { severity } of vulnerabilities) if (rankOf(severity) > rankOf(worst)) worst = severity;
	return worst;
}

const softwareKey = ({ name, version, ecosystem }) => `${ecosystem ?? ''}|${name}|${version}`;

function entry(vulnerability) {
	return {
		id: vulnerability.cveID,
		severity: vulnerability.severity ?? undefined,
		score: vulnerability.cvssScore,
		sources: vulnerability.sources ?? ['nvd'],
		link: vulnerabilityLink(vulnerability.cveID),
		toVerify: Boolean(vulnerability.versionNormalized || vulnerability.platformDependent)
	};
}

// item: { kind: 'machine' | 'application', name, hostname, osFamily, organization, minSeverity }.
// vulnerabilities: the item's new CVEs (machineVulnerabilities-like entries). packageFlags: for an
// application, `ecosystem|name|version` => { direct, dev }.
export function buildItemNotification({ item, vulnerabilities, packageFlags = new Map() }) {
	const ordered = vulnerabilities.map(vulnerability => ({ vulnerability, entry: entry(vulnerability) })).toSorted((left, right) => byGravity(left.entry, right.entry));
	const listed = ordered.slice(0, MAX_LISTED);

	const groups = new Map();
	for (const { vulnerability, entry: listedEntry } of listed) {
		for (const software of vulnerability.software) {
			const key = softwareKey(software);
			if (!groups.has(key)) {
				const flags = packageFlags.get(key);
				groups.set(key, { software: { name: software.name, version: software.version, ecosystem: software.ecosystem, direct: flags?.direct, dev: flags?.dev }, vulnerabilities: [] });
			}
			groups.get(key).vulnerabilities.push(listedEntry);
		}
	}
	const sortedGroups = [...groups.values()]
		.map(group => ({ ...group, worst: worstOf(group.vulnerabilities) }))
		.toSorted((left, right) => rankOf(right.worst) - rankOf(left.worst) || right.vulnerabilities.length - left.vulnerabilities.length || left.software.name.localeCompare(right.software.name));

	const bySeverity = Object.fromEntries([...SEVERITIES, 'UNSCORED'].map(severity => [severity, 0]));
	for (const { entry: counted } of ordered) bySeverity[RANK[counted.severity] ? counted.severity : 'UNSCORED'] += 1;

	return {
		item,
		counts: { total: ordered.length, bySeverity },
		worst: worstOf(ordered.map(({ entry: counted }) => counted)),
		groups: sortedGroups,
		hidden: ordered.length - listed.length
	};
}
