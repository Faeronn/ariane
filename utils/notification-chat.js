// Slack and Discord rendering of an item notification. First version, laid out in the chat phase.

const titleOf = ({ item }) => (item.kind === 'application' ? `${item.name} (application sur ${item.hostname})` : `${item.name} (poste)`);
const vulnerabilityLine = ({ id, severity, link }) => `• ${id} ${severity ?? 'non notée'} ${link}`;
const groupText = ({ software, vulnerabilities }) => [`${software.name} ${software.version}`, ...vulnerabilities.map(vulnerability => vulnerabilityLine(vulnerability))].join('\n');

export function renderSlack(notification) {
	const summary = `${titleOf(notification)} : ${notification.counts.total} nouvelle(s) vulnérabilité(s)`;
	const sections = notification.groups.map(group => ({ type: 'section', text: { type: 'mrkdwn', text: groupText(group).slice(0, 3000) } }));
	return { text: summary, blocks: [{ type: 'section', text: { type: 'mrkdwn', text: `*${summary}*` } }, ...sections].slice(0, 50) };
}

export function renderDiscord(notification) {
	return { embeds: [{ title: titleOf(notification).slice(0, 256), description: notification.groups.map(group => groupText(group)).join('\n\n').slice(0, 4096) }] };
}
