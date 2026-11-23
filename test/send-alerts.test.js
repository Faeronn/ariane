import { describe, it, before, beforeEach, afterEach, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { runOnce } from '../jobs/send-alerts.js';
import { getTransporter } from '../utils/mailer.js';
import { reset, TEST_ORG_ID } from './helpers/database.js';
import { captureLogs } from './helpers/fixtures.js';
import { startWebhookStub } from './helpers/webhook-stub.js';
import database from '../utils/database.js';

const CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';
const OTHER_ORG_ID = 2;

// Organization 1: two verified admins, a viewer, an unverified admin. Machine 1 "web-01" runs
// openssl 3.0.0 (CVE-2000-0001 CRITICAL, CVE-2000-0002 MEDIUM); its application 1 "shop" has
// express 4.17.1 (CVE-2024-29041 HIGH). Every state is new (unsent).
let sent;
let sendMail;
beforeEach(async () => {
	await reset();
	await database.query("INSERT INTO organizations (orgID, name, createdAt) VALUES (?, 'Other', UTC_TIMESTAMP())", [OTHER_ORG_ID]);
	await database.query(`INSERT INTO users (orgID, username, role, isVerified) VALUES
		(?, 'alice@ariane.test', 'admin', 1), (?, 'bob@ariane.test', 'admin', 1), (?, 'carol@ariane.test', 'viewer', 1),
		(?, 'eve@ariane.test', 'admin', 0), (?, 'dave@other.test', 'admin', 1)`, [TEST_ORG_ID, TEST_ORG_ID, TEST_ORG_ID, TEST_ORG_ID, OTHER_ORG_ID]);
	await database.query(`INSERT INTO machines (machineID, orgID, hostname, apiKeyHash, createdAt, osFamily) VALUES (1, ?, 'web-01', REPEAT('a', 64), UTC_TIMESTAMP(), 'linux')`, [TEST_ORG_ID]);
	await database.query('INSERT INTO inventory_snapshot (snapshotID, machineID, collectedAt, receivedAt) VALUES (1, 1, UTC_TIMESTAMP(), UTC_TIMESTAMP())');
	await database.query("INSERT INTO installed_software (snapshotID, vendor, name, version) VALUES (1, 'openssl', 'openssl', '3.0.0')");
	await database.query("INSERT INTO software_cpe (vendor, name, version, cpeName, status, versionNormalized) VALUES ('openssl', 'openssl', '3.0.0', ?, 'matched', 0)", [CPE]);
	for (const [cveID, score, severity] of [['CVE-2000-0001', 9.8, 'CRITICAL'], ['CVE-2000-0002', 5, 'MEDIUM']]) {
		await database.query('INSERT INTO cve (cveID, cvssScore, severity) VALUES (?, ?, ?)', [cveID, score, severity]);
		await database.query('INSERT INTO cpe_cve (cpeName, cveID) VALUES (?, ?)', [CPE, cveID]);
		await database.query('INSERT INTO item_cve_state (itemType, itemID, cveID, firstSeenAt) VALUES ("machine", 1, ?, UTC_TIMESTAMP())', [cveID]);
	}
	await database.query("INSERT INTO applications (applicationID, orgID, machineID, name, createdAt, lastSeenAt) VALUES (1, ?, 1, 'shop', UTC_TIMESTAMP(), UTC_TIMESTAMP())", [TEST_ORG_ID]);
	await database.query('INSERT INTO application_snapshot (snapshotID, applicationID, receivedAt) VALUES (1, 1, UTC_TIMESTAMP())');
	await database.query("INSERT INTO application_dependency (snapshotID, ecosystem, name, version, direct, dev) VALUES (1, 'npm', 'express', '4.17.1', 1, 0)");
	await database.query("INSERT INTO cve (cveID, cvssScore, severity) VALUES ('CVE-2024-29041', 7.5, 'HIGH')");
	await database.query("INSERT INTO package_vuln (ecosystem, name, version, cveID, source) VALUES ('npm', 'express', '4.17.1', 'CVE-2024-29041', 'osv')");
	await database.query('INSERT INTO item_cve_state (itemType, itemID, cveID, firstSeenAt) VALUES ("application", 1, "CVE-2024-29041", UTC_TIMESTAMP())');

	sent = [];
	sendMail = mock.method(getTransporter(), 'sendMail', async mail => {
		sent.push(mail);
		return { messageId: `m${sent.length}` };
	});
});
afterEach(() => sendMail.mock.restore());
after(() => database.end());

const stateOf = column => database.query(`SELECT itemType, cveID, ${column} IS NOT NULL AS done FROM item_cve_state ORDER BY itemType = "application", cveID`)
	.then(rows => rows.map(({ itemType, cveID, done }) => `${itemType[0]}:${cveID}:${done ? 'done' : 'pending'}`));
// Alerts still waiting on `column`'s channel.
const pendingOn = column => stateOf(column).then(states => states.filter(state => state.endsWith('pending')));

describe('email alerts per item', () => {
	it('mails one message per item to the verified admins, with that item\'s CVEs at or above the threshold', async () => {
		await runOnce();
		assert.equal(sent.length, 2);
		assert.ok(sent.every(mail => mail.to.join(',') === 'alice@ariane.test,bob@ariane.test'));
		const machine = sent.find(mail => mail.subject.includes('web-01') && !mail.subject.includes('shop'));
		const application = sent.find(mail => mail.subject.includes('shop'));
		assert.match(machine.subject, /web-01/);
		assert.match(machine.html, /CVE-2000-0001/);
		assert.doesNotMatch(machine.html, /CVE-2000-0002|CVE-2024-29041/);
		assert.match(application.subject, /shop/);
		assert.match(application.html, /CVE-2024-29041/);
		assert.doesNotMatch(application.html, /CVE-2000-0001/);
		assert.ok(sent.every(mail => mail.text.length > 0), 'a plain-text part goes with the HTML');
	});

	it('marks every alert handled, including the one below the threshold, and sends nothing more', async () => {
		await runOnce();
		assert.deepEqual(await stateOf('emailSentAt'), ['m:CVE-2000-0001:done', 'm:CVE-2000-0002:done', 'a:CVE-2024-29041:done']);
		await runOnce();
		assert.equal(sent.length, 2);
	});

	it('keeps only the failed item unsent when the transport fails for it, and sends it next tick', async () => {
		sendMail.mock.mockImplementationOnce(() => Promise.reject(new Error('smtp down')));
		const logs = captureLogs();
		try {
			await runOnce();
		} finally {
			logs.restore();
		}
		assert.ok(logs.lines.some(line => line.level === 50 && /delivery failed/.test(line.msg)));
		const pending = await pendingOn('emailSentAt');
		assert.equal(pending.length, 1);
		await runOnce();
		assert.deepEqual(await pendingOn('emailSentAt'), []);
		assert.equal(sent.length, 2);
	});

	it('sends nothing and marks alerts handled when email alerts are off', async () => {
		await database.query('UPDATE organizations SET alertEmailEnabled = 0');
		await runOnce();
		assert.equal(sent.length, 0);
		assert.deepEqual(await pendingOn('emailSentAt'), []);
	});

	it('escapes HTML coming from inventories', async () => {
		await database.query("UPDATE machines SET hostname = '<b>web</b>'");
		await runOnce();
		const machineMail = sent.find(mail => mail.subject.includes('<b>web</b>'));
		assert.ok(machineMail);
		assert.match(machineMail.html, /&lt;b&gt;web&lt;\/b&gt;/);
		assert.doesNotMatch(machineMail.html, /<b>web<\/b>/);
	});

	it('ignores the items of revoked machines', async () => {
		await database.query('UPDATE machines SET revokedAt = UTC_TIMESTAMP()');
		await runOnce();
		assert.equal(sent.length, 0);
	});
});

describe('webhook alerts per item', () => {
	let hook;
	before(async () => {
		hook = await startWebhookStub();
		process.env.WEBHOOK_TEST_ORIGIN = hook.origin;
	});
	after(async () => {
		delete process.env.WEBHOOK_TEST_ORIGIN;
		await hook.close();
	});
	beforeEach(async () => {
		hook.reset();
		await database.query('UPDATE organizations SET alertWebhookKind = ?, alertWebhookUrl = ? WHERE orgID = ?', ['discord', `${hook.origin}/hook`, TEST_ORG_ID]);
	});

	it('posts one message per item', async () => {
		await runOnce();
		assert.equal(hook.posts.length, 2);
		const bodies = hook.posts.map(({ body }) => JSON.stringify(body));
		assert.ok(bodies.some(body => body.includes('web-01') && body.includes('CVE-2000-0001') && !body.includes('CVE-2024-29041')));
		assert.ok(bodies.some(body => body.includes('shop') && body.includes('CVE-2024-29041')));
		assert.deepEqual(await pendingOn('webhookSentAt'), []);
	});

	it('keeps the webhook unsent when it fails, without affecting the email', async () => {
		hook.answer(500);
		const logs = captureLogs();
		try {
			await runOnce();
		} finally {
			logs.restore();
		}
		const unposted = await pendingOn('webhookSentAt');
		assert.ok(unposted.length > 0);
		assert.deepEqual(await pendingOn('emailSentAt'), []);
		hook.answer(204);
		await runOnce();
		assert.deepEqual(await pendingOn('webhookSentAt'), []);
		assert.equal(sent.length, 2);
	});

	it('never posts to a URL outside the allowlist', async () => {
		delete process.env.WEBHOOK_TEST_ORIGIN;
		const logs = captureLogs();
		try {
			await runOnce();
		} finally {
			logs.restore();
			process.env.WEBHOOK_TEST_ORIGIN = hook.origin;
		}
		assert.equal(hook.posts.length, 0);
		assert.ok(logs.lines.some(line => /refused/.test(line.err?.message)));
	});

	it('marks alerts handled without any request when the organization has no webhook', async () => {
		await database.query('UPDATE organizations SET alertWebhookKind = NULL, alertWebhookUrl = NULL');
		await runOnce();
		assert.equal(hook.posts.length, 0);
		assert.deepEqual(await pendingOn('webhookSentAt'), []);
	});
});
