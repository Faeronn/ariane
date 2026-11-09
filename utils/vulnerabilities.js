import database from './database.js';

const LATEST_SNAPSHOT_OF = 'SELECT MAX(snapshotID) FROM inventory_snapshot WHERE machineID = ?';

// CVEs affecting a machine's latest snapshot: software => software_cpe => cpe_cve => cve, one entry
// per CVE with every affected software, highest CVSS first. Shared by the vulns route, the alerts
// and the fleet summary.
export async function machineVulnerabilities(machineID) {
	const rows = await database.query(`SELECT c.cveID, c.severity, c.cvssScore, DATE_FORMAT(c.published, '%Y-%m-%dT%H:%i:%sZ') AS published, s.name, s.version, sc.versionNormalized
		FROM installed_software s
		INNER JOIN software_cpe sc ON sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version AND sc.status = 'matched'
		INNER JOIN cpe_cve cc ON cc.cpeName = sc.cpeName
		INNER JOIN cve c ON c.cveID = cc.cveID
		WHERE s.snapshotID = (${LATEST_SNAPSHOT_OF})
		ORDER BY c.cvssScore IS NULL, c.cvssScore DESC, c.cveID, s.name, s.version`, [machineID]);

	// versionNormalized: every affected software was matched on its upstream version only, so a
	// distribution backport may already fix it. One exact-version match confirms the CVE.
	const vulnerabilities = new Map();
	for (const { cveID, severity, cvssScore, published, name, version, versionNormalized } of rows) {
		if (!vulnerabilities.has(cveID)) vulnerabilities.set(cveID, { cveID, severity, cvssScore: cvssScore === null ? undefined : Number(cvssScore), published, versionNormalized: true, software: [] });
		const vulnerability = vulnerabilities.get(cveID);
		vulnerability.versionNormalized &&= Boolean(versionNormalized);
		vulnerability.software.push({ name, version });
	}
	return [...vulnerabilities.values()];
}

// Software of the machine's latest snapshot without a CPE yet (pending, unmatched or unknown).
export async function countUnmapped(machineID) {
	const [{ unmapped }] = await database.query(`SELECT COUNT(*) AS unmapped
		FROM installed_software s
		LEFT JOIN software_cpe sc ON sc.vendor = s.vendor AND sc.name = s.name AND sc.version = s.version
		WHERE s.snapshotID = (${LATEST_SNAPSHOT_OF}) AND (sc.status IS NULL OR sc.status <> 'matched')`, [machineID]);
	return Number(unmapped);
}
