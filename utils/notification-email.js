// Email rendering of an item notification: { subject, html, text }. Table layout with inline styles
// only (Outlook and webmails ignore style sheets), no image; severities carry a text label, never
// color alone; the plain-text part says the same.

const escapeHtml = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

const SEVERITY = {
	CRITICAL: { label: 'Critique', plural: 'critiques', color: '#b91c1c' },
	HIGH: { label: 'Haute', plural: 'hautes', color: '#c2410c' },
	MEDIUM: { label: 'Moyenne', plural: 'moyennes', color: '#a16207' },
	LOW: { label: 'Faible', plural: 'faibles', color: '#4b5563' },
	UNSCORED: { label: 'Non notée', plural: 'non notées', color: '#6b7280' }
};
const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNSCORED'];
const OS_LABEL = { windows: 'Windows', linux: 'Linux' };
const FONT = "font-family: 'Segoe UI', Arial, sans-serif;";

const severityKey = severity => (SEVERITY[severity] ? severity : 'UNSCORED');
const plural = (count, singular, many) => (count === 1 ? `${count} ${singular}` : `${count} ${many}`);
const osOf = ({ osFamily }) => (OS_LABEL[osFamily] ? ` (${OS_LABEL[osFamily]})` : '');

// "gesdoc2 — application sur DESKTOP-MMMGL5M (Windows)" / "DESKTOP-MMMGL5M — poste (Windows)".
function itemTitle({ item }) {
	return item.kind === 'application' ? `${item.name} — application sur ${item.hostname}${osOf(item)}` : `${item.name} — poste${osOf(item)}`;
}

// "3 nouvelles vulnérabilités, dont 1 critique": the worst scored severity is named.
function headline({ counts }) {
	const total = plural(counts.total, 'nouvelle vulnérabilité', 'nouvelles vulnérabilités');
	const worst = ['CRITICAL', 'HIGH'].find(severity => counts.bySeverity[severity] > 0);
	if (!worst) return total;
	const count = counts.bySeverity[worst];
	return `${total}, dont ${count} ${count === 1 ? SEVERITY[worst].label.toLowerCase() : SEVERITY[worst].plural}`;
}

// Tags of a software: ecosystem and direct/transitive/dev for a package.
function tagsOf({ ecosystem, direct, dev }) {
	if (!ecosystem) return [];
	const tags = [ecosystem];
	if (direct !== undefined) tags.push(direct ? 'directe' : 'transitive');
	if (dev) tags.push('développement');
	return tags;
}

const badge = severity => {
	const { label, color } = SEVERITY[severityKey(severity)];
	return `<span style="display: inline-block; padding: 2px 8px; border-radius: 3px; background: ${color}; color: #ffffff; font-size: 12px; font-weight: bold;">${label}</span>`;
};

function countsRow({ counts }) {
	const badges = ORDER.filter(severity => counts.bySeverity[severity] > 0).map(severity => `${badge(severity)} <span style="font-size: 13px; color: #111827;">${counts.bySeverity[severity]}</span>`);
	return `<tr><td style="padding: 12px 24px; border-bottom: 1px solid #e5e7eb; ${FONT}">${badges.join('&nbsp;&nbsp;&nbsp;')}</td></tr>`;
}

function vulnerabilityRow(vulnerability) {
	const score = vulnerability.score === undefined ? '—' : String(vulnerability.score);
	const note = vulnerability.toVerify ? '<br><span style="font-size: 12px; color: #6b7280;">à vérifier : correctif de distribution ou plateforme possible</span>' : '';
	const cell = 'padding: 6px 8px; border-top: 1px solid #f3f4f6; font-size: 13px;';
	return `<tr>
		<td style="${cell}"><a href="${escapeHtml(vulnerability.link)}" style="color: #1d4ed8;">${escapeHtml(vulnerability.id)}</a>${note}</td>
		<td style="${cell}">${badge(vulnerability.severity)}</td>
		<td style="${cell} text-align: right;">${escapeHtml(score)}</td>
		<td style="${cell} color: #6b7280;">${escapeHtml(vulnerability.sources.join(' + '))}</td>
	</tr>`;
}

function groupBlock({ software, vulnerabilities }) {
	const tags = tagsOf(software).map(tag => `<span style="font-size: 12px; color: #4b5563; border: 1px solid #d1d5db; border-radius: 3px; padding: 1px 6px;">${escapeHtml(tag)}</span>`).join(' ');
	return `<tr><td style="padding: 16px 24px 4px 24px; ${FONT}">
		<div style="font-size: 15px; font-weight: bold; color: #111827;">${escapeHtml(software.name)} <span style="font-weight: normal; color: #374151;">${escapeHtml(software.version)}</span> ${tags}</div>
		<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top: 6px; border-collapse: collapse; ${FONT}">
			${vulnerabilities.map(vulnerability => vulnerabilityRow(vulnerability)).join('')}
		</table>
	</td></tr>`;
}

function footerRow({ item, hidden }) {
	const more = hidden > 0 ? `<p style="margin: 0 0 8px 0;">+${hidden} autre(s), moins graves : voir l’API Ariane.</p>` : '';
	return `<tr><td style="padding: 16px 24px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #6b7280; ${FONT}">
		${more}<p style="margin: 0;">Ariane · ${escapeHtml(item.organization)} · seuil d’alerte ${escapeHtml(SEVERITY[severityKey(item.minSeverity)].label.toLowerCase())} · réglages : PUT /organization/alerts</p>
	</td></tr>`;
}

function renderHtml(notification) {
	return `<!DOCTYPE html><html lang="fr"><body style="margin: 0; padding: 0; background: #f3f4f6;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background: #f3f4f6; padding: 24px 0;"><tr><td align="center">
	<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width: 640px; background: #ffffff; border: 1px solid #e5e7eb; border-top: 4px solid ${SEVERITY[severityKey(notification.worst)].color};">
		<tr><td style="padding: 20px 24px 8px 24px; ${FONT}">
			<div style="font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px;">Ariane · nouvelles vulnérabilités</div>
			<div style="font-size: 20px; font-weight: bold; color: #111827; margin-top: 4px;">${escapeHtml(itemTitle(notification))}</div>
			<div style="font-size: 14px; color: #374151; margin-top: 4px;">${escapeHtml(headline(notification))}</div>
		</td></tr>
		${countsRow(notification)}
		${notification.groups.map(group => groupBlock(group)).join('')}
		${footerRow(notification)}
	</table>
</td></tr></table>
</body></html>`;
}

function textVulnerability(vulnerability) {
	const score = vulnerability.score === undefined ? '' : ` ${vulnerability.score}`;
	const toVerify = vulnerability.toVerify ? ' (à vérifier)' : '';
	return `    ${vulnerability.id}  ${SEVERITY[severityKey(vulnerability.severity)].label}${score}  [${vulnerability.sources.join('+')}]${toVerify}\n    ${vulnerability.link}`;
}

function renderText(notification) {
	const { counts, groups, hidden, item } = notification;
	const countLine = ORDER.filter(severity => counts.bySeverity[severity] > 0).map(severity => `${SEVERITY[severity].label} ${counts.bySeverity[severity]}`).join(' · ');
	const blocks = groups.map(({ software, vulnerabilities }) => {
		const tags = tagsOf(software);
		const header = tags.length > 0 ? `${software.name} ${software.version} (${tags.join(', ')})` : `${software.name} ${software.version}`;
		return [header, ...vulnerabilities.map(vulnerability => textVulnerability(vulnerability))].join('\n');
	});
	return [
		itemTitle(notification),
		headline(notification),
		countLine,
		'',
		...blocks.flatMap(block => [block, '']),
		hidden > 0 ? `+${hidden} autre(s), moins graves : voir l’API Ariane.` : '',
		`Ariane · ${item.organization} · seuil d’alerte ${SEVERITY[severityKey(item.minSeverity)].label.toLowerCase()} · réglages : PUT /organization/alerts`
	].filter((line, index, lines) => line !== '' || lines[index - 1] !== '').join('\n').trim();
}

export function renderEmail(notification) {
	return {
		subject: `[Ariane] ${itemTitle(notification)} : ${headline(notification)}`,
		html: renderHtml(notification),
		text: renderText(notification)
	};
}
