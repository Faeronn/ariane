import { webhookUrlProblem } from './webhook-url.js';
import { renderSlack, renderDiscord } from './notification-chat.js';

const TIMEOUT_MS = 10_000;

// The message body for `kind` ('slack' or 'discord') describing one item notification.
export const renderChat = (kind, notification) => (kind === 'slack' ? renderSlack(notification) : renderDiscord(notification));

// Tests point webhooks at a local stub; outside NODE_ENV=test no override exists.
const isTestUrl = url => process.env.NODE_ENV === 'test' && Boolean(process.env.WEBHOOK_TEST_ORIGIN) && url.startsWith(`${process.env.WEBHOOK_TEST_ORIGIN}/`);

// POST the body to the webhook. The URL is re-checked against the Slack/Discord allowlist, redirects
// are not followed, and anything but a 2xx answer throws so the alerts stay unsent.
export async function postWebhook(kind, url, body) {
	const problem = webhookUrlProblem(kind, url);
	if (problem && !isTestUrl(url)) throw new Error(`Webhook URL refused: ${problem}`);

	const response = await fetch(url, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
		redirect: 'manual',
		signal: AbortSignal.timeout(TIMEOUT_MS)
	});
	if (!response.ok) throw new Error(`Webhook answered ${response.status}`);
}
