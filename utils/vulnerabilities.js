import database from './database.js';
import { platformsMayApply } from './platform.js';

const LATEST_SNAPSHOT_OF = 'SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = ?';
const CVE_COLUMNS = "c.cveID, c.severity, c.cvssScore, DATE_FORMAT(c.published, '%Y-%m-%dT%H:%i:%sZ') AS published";

// Latest dependency snapshot of each application (narrowed by `a.machineID = ?` or `a.applicationID = ?`).
const LATEST_DEPENDENCIES = `FROM applications a
	INNER JOIN application_snapshot s ON s.applicationID = a.applicationID
		AND s.snapshotID = (SELECT MAX(latest.snapshotID) FROM application_snapshot latest WHERE latest.applicationID = a.applicationID)
	INNER JOIN application_dependency d ON d.snapshotID = s.snapshotID`;
const DEPENDENCY_COLUMNS = 'd.name, d.version, d.ecosystem, d.direct, d.dev, a.name AS application';
const SCOPES = new Set(['machineID', 'applicationID']);

// Installed programs of the machine's latest snapshot, through their CPE (NVD).
function programRows(machineID) {
	return database.query(`SELECT ${CVE_COLUMNS}, s.name, s.version, sc.versionNormalized, cc.platforms
		FROM installed_software s
		INNER JOIN software_cpe sc ON sc.ecosystem = '' AND sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version AND sc.status = 'matched'
		INNER JOIN cpe_cve cc ON cc.cpeName = sc.cpeName
		INNER JOIN cve c ON c.cveID = cc.cveID
		WHERE s.snapshotID = (${LATEST_SNAPSHOT_OF})`, [machineID]);
}

// Dependencies of the applications in scope: direct ones through their CPE (NVD), all through the
// package advisories (OSV, and Packagist for Composer), each link with its source.
function dependencyRows(scope, id) {
	if (!SCOPES.has(scope)) throw new Error(`Unknown scope ${scope}`);
	const nvd = database.query(`SELECT ${CVE_COLUMNS}, ${DEPENDENCY_COLUMNS}, cc.platforms
		${LATEST_DEPENDENCIES}
		INNER JOIN software_cpe sc ON d.direct = 1 AND sc.ecosystem = d.ecosystem AND sc.packageName = d.name AND sc.version = d.version AND sc.status = 'matched'
		INNER JOIN cpe_cve cc ON cc.cpeName = sc.cpeName
		INNER JOIN cve c ON c.cveID = cc.cveID
		WHERE a.${scope} = ?`, [id]);
	const advisories = database.query(`SELECT ${CVE_COLUMNS}, ${DEPENDENCY_COLUMNS}, pv.source
		${LATEST_DEPENDENCIES}
		INNER JOIN package_vuln pv ON pv.ecosystem = d.ecosystem AND pv.name = d.name AND pv.version = d.version
		INNER JOIN cve c ON c.cveID = pv.cveID
		WHERE a.${scope} = ?`, [id]);
	return Promise.all([nvd, advisories]);
}

const byScore = (left, right) => (right.cvssScore ?? -1) - (left.cvssScore ?? -1) || left.cveID.localeCompare(right.cveID);
const softwareOrder = item => `${item.application ?? ''}|${item.name}|${item.version}`;
const bySoftware = (left, right) => softwareOrder(left).localeCompare(softwareOrder(right));

// One entry per vulnerability, whatever reached it. versionNormalized: every affected software was
// matched on its upstream version only (a distribution backport may fix it), one exact match
// confirms it. platformDependent: every link needs a platform the machine may or may not run;
// links whose platforms are all known OS families other than the machine's are dropped.
// sources: nvd (CPE), osv and packagist (package advisories).
function merge(osFamily, findings) {
	const vulnerabilities = new Map();
	for (const { row, source, software, versionNormalized } of findings) {
		const required = row.platforms ? JSON.parse(row.platforms) : [];
		if (required.length > 0 && !platformsMayApply(required, osFamily)) continue;

		if (!vulnerabilities.has(row.cveID)) {
			vulnerabilities.set(row.cveID, { cveID: row.cveID, severity: row.severity, cvssScore: row.cvssScore === null ? undefined : Number(row.cvssScore), published: row.published, versionNormalized: true, platformDependent: true, sources: [], software: [] });
		}
		const vulnerability = vulnerabilities.get(row.cveID);
		vulnerability.versionNormalized &&= versionNormalized;
		vulnerability.platformDependent &&= required.length > 0;
		if (!vulnerability.sources.includes(source)) vulnerability.sources = [...vulnerability.sources, source].toSorted();
		const known = JSON.stringify(software);
		if (!vulnerability.software.some(item => JSON.stringify(item) === known)) vulnerability.software.push(software);
	}
	return [...vulnerabilities.values()].map(vulnerability => ({ ...vulnerability, software: vulnerability.software.toSorted(bySoftware) })).toSorted(byScore);
}

const programFindings = programs => programs.map(row => ({ row, source: 'nvd', software: { name: row.name, version: row.version }, versionNormalized: Boolean(row.versionNormalized) }));
const dependency = row => ({ name: row.name, version: row.version, ecosystem: row.ecosystem, application: row.application });
const dependencyFindings = ([nvd, advisories]) => [
	...nvd.map(row => ({ row, source: 'nvd', software: dependency(row), versionNormalized: false })),
	...advisories.map(row => ({ row, source: row.source, software: dependency(row), versionNormalized: false }))
];

// Vulnerabilities of a machine: its installed programs and the dependencies of its applications,
// one entry per vulnerability, highest CVSS first. Shared by the vulns route, the alerts and the
// fleet summary.
export async function machineVulnerabilities(machineID) {
	const [[machine], programs, dependencies] = await Promise.all([
		database.query('SELECT osFamily FROM machines WHERE machineID = ?', [machineID]),
		programRows(machineID),
		dependencyRows('machineID', machineID)
	]);
	return merge(machine?.osFamily, [...programFindings(programs), ...dependencyFindings(dependencies)]);
}

// Vulnerabilities of the machine's installed programs only (the machine as an alert item; its
// applications are items of their own).
export async function programVulnerabilities(machineID) {
	const [[machine], programs] = await Promise.all([
		database.query('SELECT osFamily FROM machines WHERE machineID = ?', [machineID]),
		programRows(machineID)
	]);
	return merge(machine?.osFamily, programFindings(programs));
}

// Vulnerabilities of one application's latest dependencies, entries flagged `direct` / `dev` when
// every affected package of the entry is.
export async function applicationVulnerabilities(applicationID) {
	const [[application], dependencies] = await Promise.all([
		database.query('SELECT m.osFamily FROM applications a INNER JOIN machines m ON m.machineID = a.machineID WHERE a.applicationID = ?', [applicationID]),
		dependencyRows('applicationID', applicationID)
	]);
	const rows = dependencies.flat();
	return merge(application?.osFamily, dependencyFindings(dependencies)).map(vulnerability => {
		const affected = rows.filter(row => row.cveID === vulnerability.cveID);
		return { ...vulnerability, direct: affected.some(row => row.direct), dev: affected.every(row => row.dev) };
	});
}

// Software of the machine's latest snapshot without a CPE yet (pending, unmatched or unknown).
export async function countUnmapped(machineID) {
	const [{ unmapped }] = await database.query(`SELECT COUNT(*) AS unmapped
		FROM installed_software s
		LEFT JOIN software_cpe sc ON sc.ecosystem = '' AND sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
		WHERE s.snapshotID = (${LATEST_SNAPSHOT_OF}) AND (sc.status IS NULL OR sc.status <> 'matched')`, [machineID]);
	return Number(unmapped);
}
