// Only Slack and Discord incoming-webhook URLs over https can be stored or called: the API never
// POSTs to an arbitrary address an admin typed (SSRF towards internal services).

const ALLOWED = {
	slack: { hosts: new Set(['hooks.slack.com']), path: '/services/' },
	discord: { hosts: new Set(['discord.com', 'discordapp.com']), path: '/api/webhooks/' }
};

export const WEBHOOK_KINDS = Object.keys(ALLOWED);

// The reason `url` is refused for `kind`, or undefined when it is acceptable.
export function webhookUrlProblem(kind, url) {
	const rule = ALLOWED[kind];
	if (!rule) return 'unknown webhook kind';
	let parsed;
	try {
		parsed = new URL(url);
	} catch {
		return 'not a URL';
	}
	if (parsed.protocol !== 'https:') return 'https is required';
	if (parsed.username || parsed.password || parsed.port) return 'credentials and custom ports are not allowed';
	if (!rule.hosts.has(parsed.hostname) || !parsed.pathname.startsWith(rule.path)) return `only ${kind} webhook URLs are allowed`;
}

// Scheme and host only: the path of a webhook URL is its secret.
export const maskWebhookUrl = url => (url ? `${new URL(url).origin}/…` : url);
