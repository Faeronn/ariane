// Email rendering of an item notification: { subject, html, text }. First version, laid out in the
// email phase.

const escapeHtml = value => String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');

const titleOf = ({ item }) => (item.kind === 'application' ? `${item.name} (application sur ${item.hostname})` : `${item.name} (poste)`);
const severityOf = ({ severity, score }) => [severity ?? 'non notée', score].filter(value => value !== undefined).join(' ');
const textLine = vulnerability => `  ${vulnerability.id} ${severityOf(vulnerability)}`;
const htmlLine = vulnerability => `<li><a href="${escapeHtml(vulnerability.link)}">${escapeHtml(vulnerability.id)}</a> ${escapeHtml(severityOf(vulnerability))}</li>`;
const softwareLabel = ({ name, version }) => `${name} ${version}`;

export function renderEmail(notification) {
	const { counts, groups, hidden } = notification;
	const subject = `[Ariane] ${titleOf(notification)} : ${counts.total} nouvelle(s) vulnérabilité(s)`;
	const textGroups = groups.map(({ software, vulnerabilities }) => [softwareLabel(software), ...vulnerabilities.map(vulnerability => textLine(vulnerability))].join('\n'));
	const text = [subject, '', ...textGroups, hidden > 0 ? `+${hidden} autre(s)` : ''].join('\n').trimEnd();
	const htmlGroups = groups.map(({ software, vulnerabilities }) => `<h3>${escapeHtml(softwareLabel(software))}</h3><ul>${vulnerabilities.map(vulnerability => htmlLine(vulnerability)).join('')}</ul>`);
	return { subject, html: `<div><h2>${escapeHtml(titleOf(notification))}</h2>${htmlGroups.join('')}</div>`, text };
}
