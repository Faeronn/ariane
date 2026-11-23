import { webhookUrlProblem } from './webhook-url.js';
import { vulnerabilityLink } from './vulnerability-link.js';

const TIMEOUT_MS = 10_000;
// Platform limits: Slack section text 3000 chars and 50 blocks; Discord content 2000 chars,
// 10 embeds, embed title 256 and description 4096 chars.
const SLACK_TEXT = 3000;
const SLACK_BLOCKS = 50;
const DISCORD_CONTENT = 2000;
const DISCORD_EMBEDS = 10;
const DISCORD_TITLE = 256;
const DISCORD_DESCRIPTION = 4096;

const truncate = (text, max) => (text.length <= max ? text : `${text.slice(0, max - 1)}…`);
const summaryOf = digest => `${digest.total} nouvelle(s) vulnérabilité(s) - ${digest.organization}`;

// A program as `name version`, a dependency with its application: `express 4.17.1 (gesdoc2)`.
const affectedSoftware = ({ name, version, application }) => (application ? `${name} ${version} (${application})` : `${name} ${version}`);

function line({ cveID, severity, cvssScore, software, versionNormalized, platformDependent }) {
	const score = cvssScore === undefined ? 'score en attente' : `${severity} ${cvssScore}`;
	const affected = software.map(item => affectedSoftware(item)).join(', ');
	const toVerify = versionNormalized || platformDependent ? ' (à vérifier)' : '';
	return `• ${cveID} (${score}) : ${affected}${toVerify} ${vulnerabilityLink(cveID)}`;
}

const machineText = ({ hostname, vulnerabilities }) => vulnerabilities.map(vulnerability => line(vulnerability)).join('\n').replace(/^/, `${hostname}\n`);

// The message body for `kind` ('slack' or 'discord') listing the digest's CVEs per machine.
export function formatDigest(kind, digest) {
	if (kind === 'slack') {
		const sections = digest.machines.map(machine => ({ type: 'section', text: { type: 'mrkdwn', text: truncate(machineText(machine), SLACK_TEXT) } }));
		return {
			text: summaryOf(digest),
			blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `*${summaryOf(digest)}*` } }, ...sections].slice(0, SLACK_BLOCKS)
		};
	}
	return {
		content: truncate(summaryOf(digest), DISCORD_CONTENT),
		embeds: digest.machines.slice(0, DISCORD_EMBEDS).map(({ hostname, vulnerabilities }) => ({
			title: truncate(hostname, DISCORD_TITLE),
			description: truncate(vulnerabilities.map(vulnerability => line(vulnerability)).join('\n'), DISCORD_DESCRIPTION)
		}))
	};
}

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
