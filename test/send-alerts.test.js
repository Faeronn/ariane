import { describe, it, beforeEach, afterEach, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { runOnce } from '../jobs/send-alerts.js';
import { getTransporter } from '../utils/mailer.js';
import { reset, TEST_ORG_ID } from './helpers/database.js';
import { captureLogs } from './helpers/fixtures.js';
import database from '../utils/database.js';

const CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';
const OTHER_ORG_ID = 2;

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
		await database.query('INSERT INTO machine_cve_state (machineID, cveID, firstSeenAt) VALUES (1, ?, UTC_TIMESTAMP())', [cveID]);
	}
	sent = [];
	sendMail = mock.method(getTransporter(), 'sendMail', async mail => {
		sent.push(mail);
		return { messageId: `m${sent.length}` };
	});
});
afterEach(() => sendMail.mock.restore());
after(() => database.end());

const emailState = () => database.query('SELECT cveID, emailSentAt IS NOT NULL AS sent FROM machine_cve_state ORDER BY cveID')
	.then(rows => rows.map(({ cveID, sent: done }) => `${cveID}:${done ? 'sent' : 'unsent'}`));

describe('email alert digest', () => {
	it('mails one digest to the verified admins listing the CVEs at or above the threshold', async () => {
		await runOnce();
		assert.equal(sent.length, 1);
		assert.deepEqual(sent[0].to, ['alice@ariane.test', 'bob@ariane.test']);
		assert.match(sent[0].subject, /1 nouvelle\(s\) vulnérabilité\(s\) - Test/);
		assert.match(sent[0].html, /web-01/);
		assert.match(sent[0].html, /https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2000-0001/);
		assert.match(sent[0].html, /openssl 3\.0\.0/);
		assert.doesNotMatch(sent[0].html, /CVE-2000-0002/);
	});

	it('marks every alert handled, including the one below the threshold, and sends nothing more', async () => {
		await runOnce();
		assert.deepEqual(await emailState(), ['CVE-2000-0001:sent', 'CVE-2000-0002:sent']);
		await runOnce();
		assert.equal(sent.length, 1);
	});

	it('keeps alerts unsent when the transport fails, and sends them on the next tick', async () => {
		sendMail.mock.mockImplementationOnce(() => Promise.reject(new Error('smtp down')));
		const logs = captureLogs();
		try {
			await runOnce();
		} finally {
			logs.restore();
		}
		assert.ok(logs.lines.some(line => line.level === 50 && /delivery failed/.test(line.msg)));
		assert.deepEqual(await emailState(), ['CVE-2000-0001:unsent', 'CVE-2000-0002:sent']);

		await runOnce();
		assert.equal(sent.length, 1);
		assert.deepEqual(await emailState(), ['CVE-2000-0001:sent', 'CVE-2000-0002:sent']);
	});

	it('sends nothing and marks alerts handled when email alerts are off', async () => {
		await database.query('UPDATE organizations SET alertEmailEnabled = 0');
		await runOnce();
		assert.equal(sent.length, 0);
		assert.deepEqual(await emailState(), ['CVE-2000-0001:sent', 'CVE-2000-0002:sent']);
	});

	it('marks CVEs to verify when the match is uncertain, and escapes HTML', async () => {
		await database.query('UPDATE software_cpe SET versionNormalized = 1');
		await database.query("UPDATE machines SET hostname = '<b>web</b>'");
		await runOnce();
		assert.match(sent[0].html, /à vérifier/);
		assert.match(sent[0].html, /&lt;b&gt;web&lt;\/b&gt;/);
	});
});
