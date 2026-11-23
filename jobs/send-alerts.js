import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import { programVulnerabilities, applicationVulnerabilities } from '../utils/vulnerabilities.js';
import { sendAlertDigest } from '../utils/mailer.js';
import { formatDigest, postWebhook } from '../utils/webhook.js';
import baseLogger from '../utils/logger.js';

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const MAX_DIGEST_ENTRIES = 100;
const logger = baseLogger.child({ job: 'send-alerts' });

// A CVE NVD has not scored yet is always reported: unknown is not low.
const meetsThreshold = (severity, minSeverity) => !SEVERITY_RANK[severity] || SEVERITY_RANK[severity] >= SEVERITY_RANK[minSeverity];

// Open CVE states of the organization's items (machines and applications of active machines) not
// yet delivered on `column`'s channel, with a label for each item.
function unsentRows(orgID, column) {
	return database.query(`SELECT st.itemType, st.itemID, st.cveID, c.severity,
			IF(st.itemType = 'machine', m.hostname, CONCAT(a.name, ' (', host.hostname, ')')) AS label
		FROM item_cve_state st
		LEFT JOIN machines m ON st.itemType = 'machine' AND m.machineID = st.itemID
		LEFT JOIN applications a ON st.itemType = 'application' AND a.applicationID = st.itemID
		LEFT JOIN machines host ON host.machineID = a.machineID
		LEFT JOIN cve c ON c.cveID = st.cveID
		WHERE COALESCE(m.orgID, host.orgID) = ? AND COALESCE(m.machineID, host.machineID) IS NOT NULL
			AND COALESCE(m.revokedAt, host.revokedAt) IS NULL AND st.resolvedAt IS NULL AND st.${column} IS NULL`, [orgID]);
}

async function markSent(rows, column) {
	if (rows.length > 0) await database.batch(`UPDATE item_cve_state SET ${column} = UTC_TIMESTAMP() WHERE itemType = ? AND itemID = ? AND cveID = ?`, rows.map(({ itemType, itemID, cveID }) => [itemType, itemID, cveID]));
}

const itemVulnerabilities = (itemType, itemID) => (itemType === 'machine' ? programVulnerabilities(itemID) : applicationVulnerabilities(itemID));

// { organization, total, shown, machines: [{ hostname, vulnerabilities }] } from the rows, with the
// current details (score, software, flags) of each CVE; at most MAX_DIGEST_ENTRIES shown.
async function buildDigest(organization, rows) {
	const byItem = Map.groupBy(rows, ({ itemType, itemID }) => `${itemType}:${itemID}`);
	const machines = [];
	let total = 0;
	let shown = 0;
	for (const machineRows of byItem.values()) {
		const wanted = new Set(machineRows.map(({ cveID }) => cveID));
		const all = await itemVulnerabilities(machineRows[0].itemType, machineRows[0].itemID);
		const vulnerabilities = all.filter(({ cveID }) => wanted.has(cveID));
		total += vulnerabilities.length;
		const kept = vulnerabilities.slice(0, Math.max(0, MAX_DIGEST_ENTRIES - shown));
		shown += kept.length;
		if (kept.length > 0) machines.push({ hostname: machineRows[0].label, vulnerabilities: kept });
	}
	machines.sort((left, right) => left.hostname.localeCompare(right.hostname));
	return { organization: organization.name, total, shown, machines };
}

async function deliverEmail(organization, digest) {
	const admins = await database.query('SELECT username FROM users WHERE orgID = ? AND role = ? AND isVerified = 1', [organization.orgID, 'admin']);
	if (admins.length === 0) return false; // kept unsent until the organization has an admin
	await sendAlertDigest(admins.map(({ username }) => username), digest);
	return true;
}

// Deliver one channel of one organization: below-threshold or disabled alerts are marked handled
// without a message; a failed delivery leaves the alerts unsent for the next tick.
async function processChannel(organization, { column, enabled, deliver }) {
	const rows = await unsentRows(organization.orgID, column);
	if (!enabled) return markSent(rows, column).then(() => 0);

	const eligible = rows.filter(({ severity }) => meetsThreshold(severity, organization.alertMinSeverity));
	await markSent(rows.filter(row => !eligible.includes(row)), column);
	if (eligible.length === 0) return 0;

	const digest = await buildDigest(organization, eligible);
	if (digest.total > 0) {
		try {
			if (!(await deliver(organization, digest))) return 0;
		} catch (error) {
			logger.error({ err: error, orgID: organization.orgID, channel: column }, 'Alert delivery failed, retried next tick');
			return 0;
		}
	}
	await markSent(eligible, column);
	return digest.total;
}

async function deliverWebhook(organization, digest) {
	await postWebhook(organization.alertWebhookKind, organization.alertWebhookUrl, formatDigest(organization.alertWebhookKind, digest));
	return true;
}

// Each channel keeps its own sent marker: a failing webhook never blocks or repeats the email.
const channelsOf = organization => [
	{ column: 'emailSentAt', enabled: organization.alertEmailEnabled === 1, deliver: deliverEmail },
	{ column: 'webhookSentAt', enabled: Boolean(organization.alertWebhookKind && organization.alertWebhookUrl), deliver: deliverWebhook }
];

async function tick() {
	const organizations = await database.query('SELECT orgID, name, alertMinSeverity, alertEmailEnabled, alertWebhookKind, alertWebhookUrl FROM organizations');
	const summary = { delivered: 0 };
	for (const organization of organizations) {
		for (const channel of channelsOf(organization)) summary.delivered += await processChannel(organization, channel);
	}
	return summary;
}

// One delivery pass on one API instance at a time.
export function runOnce() {
	return withJobLock('send-alerts', tick);
}

export function startSendAlertsJob(intervalMs = 15 * 60_000) {
	const timer = setInterval(() => runOnce().catch(error => logger.error(error, 'Alert delivery pass failed')), intervalMs);
	timer.unref();
	return timer;
}
