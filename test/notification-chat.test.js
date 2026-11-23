import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildItemNotification } from '../utils/notification.js';
import { renderDiscord, renderSlack } from '../utils/notification-chat.js';

const ITEM = { kind: 'application', name: 'gesdoc2', hostname: 'DESKTOP-MMMGL5M', osFamily: 'windows', organization: 'artemis-rd.com', minSeverity: 'MEDIUM' };
const express = { name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'gesdoc2' };
const qs = { name: 'qs', version: '6.7.0', ecosystem: 'npm', application: 'gesdoc2' };
const vulnerability = (cveID, severity, cvssScore, software, extra = {}) => ({ cveID, severity, cvssScore, sources: ['osv'], software, ...extra });

const small = buildItemNotification({
	item: ITEM,
	vulnerabilities: [
		vulnerability('CVE-2024-0001', 'CRITICAL', 9.8, [express], { sources: ['nvd', 'osv'] }),
		vulnerability('CVE-2024-29041', 'MEDIUM', 6.1, [express]),
		vulnerability('GHSA-qs', 'HIGH', 7.5, [qs])
	],
	packageFlags: new Map([['npm|express|4.17.1', { direct: true, dev: false }], ['npm|qs|6.7.0', { direct: false, dev: false }]])
});

// 40 packages of 5 CVEs each with long names: more than any platform limit allows in one message.
const huge = buildItemNotification({
	item: ITEM,
	vulnerabilities: Array.from({ length: 200 }, (_, index) => vulnerability(`CVE-2024-${String(index).padStart(5, '0')}`, 'HIGH', 7.5, [{ name: `package-${index % 40}-${'x'.repeat(150)}`, version: '1.0.0', ecosystem: 'npm', application: 'gesdoc2' }]))
});

const discordTotal = embed => embed.title.length + embed.description.length + embed.footer.text.length + embed.fields.reduce((total, field) => total + field.name.length + field.value.length, 0);

describe('renderDiscord', () => {
	it('sends one embed titled by the item, colored by its worst severity, one field per package', () => {
		const { content, embeds } = renderDiscord(small);
		assert.equal(embeds.length, 1);
		const [embed] = embeds;
		assert.equal(embed.title, '🔴 gesdoc2 — application sur DESKTOP-MMMGL5M (Windows)');
		assert.equal(embed.color, 0xB9_1C_1C);
		assert.match(content, /gesdoc2/);
		assert.match(embed.description, /3 nouvelles vulnérabilités : 1 critique · 1 haute · 1 moyenne/);
		assert.deepEqual(embed.fields.map(({ name }) => name), ['express 4.17.1 · npm · directe', 'qs 6.7.0 · npm · transitive']);
		assert.match(embed.fields[0].value, /^🔴 \[CVE-2024-0001\]\(https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-0001\) Critique 9\.8 · nvd\+osv$/m);
		assert.match(embed.footer.text, /artemis-rd\.com · seuil d’alerte moyenne/);
	});

	it('stays within every documented limit and says what was left out', () => {
		const [embed] = renderDiscord(huge).embeds;
		assert.ok(embed.fields.length <= 25);
		assert.ok(embed.fields.every(({ name, value }) => name.length <= 256 && value.length <= 1024));
		assert.ok(discordTotal(embed) <= 6000, `total ${discordTotal(embed)}`);
		assert.equal(embed.fields.at(-1).name, 'Et aussi');
		assert.match(embed.fields.at(-1).value, /autre\(s\) logiciel\(s\), 100 vulnérabilité\(s\) moins graves/);
	});

	it('neutralizes Discord markdown coming from inventories', () => {
		const hostile = buildItemNotification({ item: { ...ITEM, name: '**bold** [x](http://evil)' }, vulnerabilities: [vulnerability('CVE-1', 'LOW', 2, [express])] });
		const { content } = renderDiscord(hostile);
		assert.ok(content.includes(String.raw`\*\*bold\*\* \[x\]\(http://evil\)`));
	});
});

describe('renderSlack', () => {
	it('sends a header, the counts, one section per package and a footer', () => {
		const { text, blocks } = renderSlack(small);
		assert.match(text, /gesdoc2 — application sur DESKTOP-MMMGL5M/);
		assert.deepEqual(blocks.map(({ type }) => type), ['header', 'context', 'section', 'section', 'context']);
		assert.equal(blocks[0].text.text, '🔴 gesdoc2 — application sur DESKTOP-MMMGL5M (Windows)');
		assert.match(blocks[2].text.text, /^\*express 4\.17\.1 · npm · directe\*\n🔴 <https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-0001\|CVE-2024-0001> Critique 9\.8 · nvd\+osv/);
	});

	it('stays within 50 blocks, 150 header and 3000 section characters', () => {
		const { blocks } = renderSlack(huge);
		assert.ok(blocks.length <= 50);
		assert.ok(blocks[0].text.text.length <= 150);
		assert.ok(blocks.filter(({ type }) => type === 'section').every(({ text }) => text.text.length <= 3000));
	});

	it('escapes Slack control characters coming from inventories', () => {
		const hostile = buildItemNotification({ item: ITEM, vulnerabilities: [vulnerability('CVE-1', 'LOW', 2, [{ name: '<!channel>&co', version: '1', ecosystem: 'npm' }])] });
		const section = renderSlack(hostile).blocks.find(({ type }) => type === 'section');
		assert.match(section.text.text, /&lt;!channel&gt;&amp;co/);
		assert.doesNotMatch(section.text.text, /<!channel>/);
	});
});
