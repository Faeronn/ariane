import { versionToShow } from './notification.js';

// Slack and Discord rendering of an item notification. Limits from the platforms' documentation
// (read 2026-11-23):
// - Discord (docs.discord.com/developers/resources/message, .../webhook): content 2000; embed title
//   256, description 4096, up to 25 fields, field name 256, value 1024, footer 2048; title,
//   description, field names and values and footer together at most 6000 characters.
// - Slack (docs.slack.dev/reference/block-kit): header text 150, section text 3000, context up to 10
//   elements, up to 50 blocks per message.
// Severities carry a word next to their colored marker, never color alone.

const SEVERITY = {
	CRITICAL: { label: 'Critique', marker: '🔴', color: 0xB9_1C_1C },
	HIGH: { label: 'Haute', marker: '🟠', color: 0xC2_41_0C },
	MEDIUM: { label: 'Moyenne', marker: '🟡', color: 0xA1_62_07 },
	LOW: { label: 'Faible', marker: '⚪', color: 0x4B_55_63 },
	UNSCORED: { label: 'Non notée', marker: '⚫', color: 0x6B_72_80 }
};
const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];
const OS_LABEL = { windows: 'Windows', linux: 'Linux' };

const DISCORD = { content: 2000, title: 256, description: 4096, fields: 25, fieldName: 256, fieldValue: 1024, footer: 2048, total: 6000 };
const SLACK = { header: 150, section: 3000, blocks: 50 };

const severityKey = severity => (SEVERITY[severity] ? severity : 'UNSCORED');
const truncate = (text, max) => (text.length <= max ? text : `${text.slice(0, max - 1)}…`);
const osOf = ({ osFamily }) => (OS_LABEL[osFamily] ? ` (${OS_LABEL[osFamily]})` : '');

function itemTitle({ item }) {
	return item.kind === 'application' ? `${item.name} — application sur ${item.hostname}${osOf(item)}` : `${item.name} — poste${osOf(item)}`;
}

function headline({ counts }) {
	const total = counts.total === 1 ? '1 nouvelle vulnérabilité' : `${counts.total} nouvelles vulnérabilités`;
	const parts = ORDER.filter(severity => counts.bySeverity[severity] > 0).map(severity => `${counts.bySeverity[severity]} ${SEVERITY[severity].label.toLowerCase()}`);
	return `${total} : ${parts.join(' · ')}`;
}

// What a message leaves out: the groups cut by the platform's limits and the CVEs over the cap.
function overflowText(groupsLeft, hidden) {
	const vulnerabilities = hidden > 0 ? `, ${hidden} vulnérabilité(s) moins graves` : '';
	return `${groupsLeft} autre(s) logiciel(s)${vulnerabilities} : voir l’API Ariane.`;
}

const footerOf = ({ item }) => `Ariane · ${item.organization} · seuil d’alerte ${SEVERITY[severityKey(item.minSeverity)].label.toLowerCase()}`;

function softwareLabel({ name, version, ecosystem, direct, dev }) {
	const tags = [];
	if (ecosystem) tags.push(ecosystem);
	if (ecosystem && direct !== undefined) tags.push(direct ? 'directe' : 'transitive');
	if (dev) tags.push('développement');
	return [[name, versionToShow({ name, version })].filter(Boolean).join(' '), ...tags].join(' · ');
}

// Lines in the order given, as many as fit in `max` characters with a "+N autres" line when cut.
function fitLines(lines, max) {
	const kept = [];
	let length = 0;
	for (const [index, line] of lines.entries()) {
		const rest = lines.length - index - 1;
		const reserve = rest > 0 ? `\n+${rest} autre(s)`.length : 0;
		if (length + line.length + 1 + reserve > max) return [...kept, `+${lines.length - index} autre(s)`].join('\n');
		kept.push(line);
		length += line.length + 1;
	}
	return kept.join('\n');
}

// Discord markdown: a backslash neutralizes formatting and link characters.
const escapeDiscord = value => String(value).replaceAll(/[\\*_`~|>[\]()#-]/g, String.raw`\$&`);

function discordLine(vulnerability) {
	const { label, marker } = SEVERITY[severityKey(vulnerability.severity)];
	const score = vulnerability.score === undefined ? '' : ` ${vulnerability.score}`;
	const toVerify = vulnerability.toVerify ? ' · à vérifier' : '';
	return `${marker} [${vulnerability.id}](${vulnerability.link}) ${label}${score} · ${vulnerability.sources.join('+')}${toVerify}`;
}

const embedSize = embed => embed.title.length + embed.description.length + embed.footer.text.length + embed.fields.reduce((total, field) => total + field.name.length + field.value.length, 0);

export function renderDiscord(notification) {
	const fields = notification.groups.map(group => ({
		name: truncate(softwareLabel(group.software), DISCORD.fieldName),
		value: fitLines(group.vulnerabilities.map(vulnerability => discordLine(vulnerability)), DISCORD.fieldValue)
	}));
	const embed = {
		title: truncate(`${SEVERITY[severityKey(notification.worst)].marker} ${itemTitle(notification)}`, DISCORD.title),
		description: truncate(escapeDiscord(headline(notification)), DISCORD.description),
		color: SEVERITY[severityKey(notification.worst)].color,
		fields: fields.slice(0, DISCORD.fields),
		footer: { text: truncate(footerOf(notification), DISCORD.footer) }
	};
	// Drop the last groups while the message is too long or has too many fields, then say how many
	// groups and CVEs were left out in a last field.
	let left = fields.length - embed.fields.length;
	const overflow = () => ({ name: 'Et aussi', value: overflowText(left, notification.hidden) });
	while (embed.fields.length > 0 && (embedSize({ ...embed, fields: [...embed.fields, overflow()] }) > DISCORD.total || (left + notification.hidden > 0 && embed.fields.length >= DISCORD.fields))) {
		embed.fields.pop();
		left += 1;
	}
	if (left > 0 || notification.hidden > 0) embed.fields.push(overflow());
	return { content: truncate(`**${escapeDiscord(itemTitle(notification))}**`, DISCORD.content), embeds: [embed] };
}

const context = text => ({ type: 'context', elements: [{ type: 'mrkdwn', text }] });

// Slack mrkdwn: &, < and > are control characters (links, mentions) and must be escaped.
const escapeSlack = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

function slackLine(vulnerability) {
	const { label, marker } = SEVERITY[severityKey(vulnerability.severity)];
	const score = vulnerability.score === undefined ? '' : ` ${vulnerability.score}`;
	const toVerify = vulnerability.toVerify ? ' · à vérifier' : '';
	return `${marker} <${vulnerability.link}|${escapeSlack(vulnerability.id)}> ${label}${score} · ${vulnerability.sources.join('+')}${toVerify}`;
}

export function renderSlack(notification) {
	const sections = notification.groups.map(group => ({
		type: 'section',
		text: { type: 'mrkdwn', text: fitLines([`*${escapeSlack(softwareLabel(group.software))}*`, ...group.vulnerabilities.map(vulnerability => slackLine(vulnerability))], SLACK.section) }
	}));
	// header + counts + sections + overflow + footer within 50 blocks.
	const room = SLACK.blocks - 4;
	const shown = sections.slice(0, room);
	const left = sections.length - shown.length;
	const overflow = left > 0 || notification.hidden > 0 ? [context(`Et aussi ${overflowText(left, notification.hidden)}`)] : [];
	return {
		text: truncate(`${itemTitle(notification)} : ${headline(notification)}`, SLACK.section),
		blocks: [
			{ type: 'header', text: { type: 'plain_text', text: truncate(`${SEVERITY[severityKey(notification.worst)].marker} ${itemTitle(notification)}`, SLACK.header), emoji: true } },
			context(escapeSlack(headline(notification))),
			...shown,
			...overflow,
			context(escapeSlack(footerOf(notification)))
		]
	};
}
