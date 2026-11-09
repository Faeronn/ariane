import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser } from './helpers/fixtures.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';

const SLACK = 'https://hooks.slack.com/services/T000/B000/secretpart';
const NONE = JSON.parse('null'); // the JSON null the API reads and returns

let server;
before(async () => { server = await startServer(); });
after(() => server.close());

let admin;
let viewer;
beforeEach(async () => {
	await reset();
	admin = await createSignedInUser(server.baseUrl, 'alice');
	viewer = await createSignedInUser(server.baseUrl, 'bob');
});

const getAlerts = user => api(server.baseUrl, 'GET', '/organization/alerts', { token: user.accessToken });
const putAlerts = (user, body) => api(server.baseUrl, 'PUT', '/organization/alerts', { token: user.accessToken, body });

describe('organization alert settings', () => {
	it('starts with HIGH, email on and no webhook', async () => {
		const { status, body } = await getAlerts(viewer);
		assert.equal(status, 200);
		assert.deepEqual(body.alerts, { minSeverity: 'HIGH', emailEnabled: true, webhookKind: NONE, webhookUrl: NONE });
	});

	it('lets an admin save a threshold and a Slack webhook', async () => {
		const saved = await putAlerts(admin, { minSeverity: 'CRITICAL', emailEnabled: true, webhookKind: 'slack', webhookUrl: SLACK });
		assert.equal(saved.status, 200);
		const { body } = await getAlerts(admin);
		assert.deepEqual(body.alerts, { minSeverity: 'CRITICAL', emailEnabled: true, webhookKind: 'slack', webhookUrl: SLACK });
	});

	it('masks the webhook URL for viewers and refuses their changes', async () => {
		await putAlerts(admin, { minSeverity: 'HIGH', emailEnabled: true, webhookKind: 'slack', webhookUrl: SLACK });
		const { body } = await getAlerts(viewer);
		assert.equal(body.alerts.webhookUrl, 'https://hooks.slack.com/…');
		const refused = await putAlerts(viewer, { minSeverity: 'LOW', emailEnabled: true });
		assert.equal(refused.status, 403);
	});

	// eslint-disable-next-line sonarjs/no-clear-text-protocols -- insecure URLs are the input the API must refuse
	for (const url of ['http://169.254.169.254/latest/meta-data', 'https://evil.example/services/x', 'http://hooks.slack.com/services/x', 'https://hooks.slack.com:8443/services/x', 'https://user:pass@hooks.slack.com/services/x', 'https://hooks.slack.com/other']) {
		it(`refuses the webhook URL ${url}`, async () => {
			const response = await putAlerts(admin, { minSeverity: 'HIGH', emailEnabled: true, webhookKind: 'slack', webhookUrl: url });
			assert.equal(response.status, 400);
			assert.match(response.body.message, /^Error : webhookUrl/);
		});
	}

	it('accepts a Discord webhook and removes the webhook when the kind is null', async () => {
		const discord = await putAlerts(admin, { minSeverity: 'HIGH', emailEnabled: false, webhookKind: 'discord', webhookUrl: 'https://discord.com/api/webhooks/1/abc' });
		assert.equal(discord.status, 200);
		const removed = await putAlerts(admin, { minSeverity: 'HIGH', emailEnabled: true, webhookKind: NONE });
		assert.deepEqual(removed.body.alerts, { minSeverity: 'HIGH', emailEnabled: true, webhookKind: NONE, webhookUrl: NONE });
	});

	it('refuses an unknown severity or a non-boolean email flag', async () => {
		const severity = await putAlerts(admin, { minSeverity: 'URGENT', emailEnabled: true });
		const flag = await putAlerts(admin, { minSeverity: 'HIGH', emailEnabled: 'yes' });
		assert.equal(severity.status, 400);
		assert.equal(flag.status, 400);
	});
});
