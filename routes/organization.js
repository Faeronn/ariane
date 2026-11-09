import authenticateUser from '../middleware/authenticate-user.js';
import requireRole from '../middleware/require-role.js';
import { WEBHOOK_KINDS, webhookUrlProblem, maskWebhookUrl } from '../utils/webhook-url.js';
import database from '../utils/database.js';
import express from 'express';
const router = express.Router();

const SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

router.use(authenticateUser);

const toSettings = row => ({ minSeverity: row.alertMinSeverity, emailEnabled: row.alertEmailEnabled === 1, webhookKind: row.alertWebhookKind, webhookUrl: row.alertWebhookUrl });

// Alert settings of the caller's organization; the webhook URL (a secret) is masked for viewers.
router.get('/alerts', async (request, response) => {
	try {
		const [row] = await database.query('SELECT alertMinSeverity, alertEmailEnabled, alertWebhookKind, alertWebhookUrl FROM organizations WHERE orgID = ?', [request.user.orgID]);
		const alerts = toSettings(row);
		if (request.user.role !== 'admin') alerts.webhookUrl = maskWebhookUrl(alerts.webhookUrl);
		return response.status(200).send({ message: 'Alert settings retrieved.', alerts });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to retrieve alert settings.' });
	}
});

// The reason a settings body is refused, or undefined.
function settingsProblem({ minSeverity, emailEnabled, webhookKind, webhookUrl } = {}) {
	if (!SEVERITIES.has(minSeverity)) return 'minSeverity must be LOW, MEDIUM, HIGH or CRITICAL.';
	if (typeof emailEnabled !== 'boolean') return 'emailEnabled must be true or false.';
	if (!webhookKind) return;
	if (!WEBHOOK_KINDS.includes(webhookKind)) return 'webhookKind must be slack, discord or null.';
	const problem = webhookUrlProblem(webhookKind, webhookUrl);
	if (problem) return `webhookUrl: ${problem}.`;
}

// Replace the organization's alert settings. A missing webhookKind removes the webhook.
router.put('/alerts', requireRole('admin'), async (request, response) => {
	const problem = settingsProblem(request.body);
	if (problem) return response.status(400).send({ message: `Error : ${problem}` });

	const { minSeverity, emailEnabled, webhookKind, webhookUrl } = request.body;
	try {
		await database.query("UPDATE organizations SET alertMinSeverity = ?, alertEmailEnabled = ?, alertWebhookKind = NULLIF(?, ''), alertWebhookUrl = NULLIF(?, '') WHERE orgID = ?",
			[minSeverity, emailEnabled, webhookKind || '', webhookKind ? webhookUrl : '', request.user.orgID]);
		const [row] = await database.query('SELECT alertMinSeverity, alertEmailEnabled, alertWebhookKind, alertWebhookUrl FROM organizations WHERE orgID = ?', [request.user.orgID]);
		return response.status(200).send({ message: 'Alert settings updated.', alerts: toSettings(row) });
	} catch (error) {
		request.log.error(error);
		return response.status(500).send({ message: 'Error : Unable to update alert settings.' });
	}
});

export default router;
