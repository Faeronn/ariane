import database from '../utils/database.js';
import { withJobLock } from '../utils/job-lock.js';
import { programVulnerabilities, applicationVulnerabilities } from '../utils/vulnerabilities.js';
import { buildItemNotification } from '../utils/notification.js';
import { sendItemNotification } from '../utils/mailer.js';
import { renderChat, postWebhook } from '../utils/webhook.js';
import baseLogger from '../utils/logger.js';

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const logger = baseLogger.child({ job: 'send-alerts' });

// A CVE nobody has scored yet is always reported: unknown is not low.
const meetsThreshold = (severity, minSeverity) => !SEVERITY_RANK[severity] || SEVERITY_RANK[severity] >= SEVERITY_RANK[minSeverity];

// Open CVE states of the organization's items (machines and applications of active machines) not
// yet delivered on `column`'s channel.
function unsentRows(orgID, column) {
	return database.query(`SELECT st.itemType, st.itemID, st.cveID, c.severity
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

// The item as notifications describe it, with its current vulnerabilities and package flags.
async function describeItem(itemType, itemID) {
	if (itemType === 'machine') {
		const [machine] = await database.query('SELECT hostname, osFamily FROM machines WHERE machineID = ?', [itemID]);
		return { item: { kind: 'machine', name: machine.hostname, hostname: machine.hostname, osFamily: machine.osFamily }, vulnerabilities: await programVulnerabilities(itemID), packageFlags: new Map() };
	}
	const [application] = await database.query('SELECT a.name, m.hostname, m.osFamily FROM applications a INNER JOIN machines m ON m.machineID = a.machineID WHERE a.applicationID = ?', [itemID]);
	const packages = await database.query('SELECT ecosystem, name, version, direct, dev FROM application_dependency WHERE snapshotID = (SELECT MAX(snapshotID) FROM application_snapshot WHERE applicationID = ?)', [itemID]);
	const packageFlags = new Map(packages.map(({ ecosystem, name, version, direct, dev }) => [`${ecosystem}|${name}|${version}`, { direct: Boolean(direct), dev: Boolean(dev) }]));
	return { item: { kind: 'application', name: application.name, hostname: application.hostname, osFamily: application.osFamily }, vulnerabilities: await applicationVulnerabilities(itemID), packageFlags };
}

async function deliverEmail(organization, notification) {
	const admins = await database.query('SELECT username FROM users WHERE orgID = ? AND role = ? AND isVerified = 1', [organization.orgID, 'admin']);
	if (admins.length === 0) return false; // kept unsent until the organization has an admin
	await sendItemNotification(admins.map(({ username }) => username), notification);
	return true;
}

async function deliverWebhook(organization, notification) {
	await postWebhook(organization.alertWebhookKind, organization.alertWebhookUrl, renderChat(organization.alertWebhookKind, notification));
	return true;
}

// One message for one item on one channel; its states are marked only once it is delivered.
async function deliverItem(organization, { column, deliver }, rows) {
	const { item, vulnerabilities, packageFlags } = await describeItem(rows[0].itemType, rows[0].itemID);
	const wanted = new Set(rows.map(({ cveID }) => cveID));
	const notification = buildItemNotification({
		item: { ...item, organization: organization.name, minSeverity: organization.alertMinSeverity },
		vulnerabilities: vulnerabilities.filter(({ cveID }) => wanted.has(cveID)),
		packageFlags
	});
	if (notification.counts.total > 0) {
		try {
			if (!(await deliver(organization, notification))) return 0;
		} catch (error) {
			logger.error({ err: error, orgID: organization.orgID, channel: column, item: `${rows[0].itemType}:${rows[0].itemID}` }, 'Alert delivery failed, retried next tick');
			return 0;
		}
	}
	await markSent(rows, column);
	return notification.counts.total;
}

// Deliver one channel of one organization, one message per item: below-threshold or disabled alerts
// are marked handled without a message; a failed item stays unsent for the next tick, the others go.
async function processChannel(organization, channel) {
	const rows = await unsentRows(organization.orgID, channel.column);
	if (!channel.enabled) return markSent(rows, channel.column).then(() => 0);

	const eligible = rows.filter(({ severity }) => meetsThreshold(severity, organization.alertMinSeverity));
	await markSent(rows.filter(row => !eligible.includes(row)), channel.column);

	let delivered = 0;
	for (const itemRows of Map.groupBy(eligible, ({ itemType, itemID }) => `${itemType}:${itemID}`).values()) {
		delivered += await deliverItem(organization, channel, itemRows);
	}
	return delivered;
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
