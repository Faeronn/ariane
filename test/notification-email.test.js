import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildItemNotification } from '../utils/notification.js';
import { renderEmail } from '../utils/notification-email.js';

const express = { name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'gesdoc2' };
const qs = { name: 'qs', version: '6.7.0', ecosystem: 'npm', application: 'gesdoc2' };
const vulnerability = (cveID, severity, cvssScore, software, extra = {}) => ({ cveID, severity, cvssScore, sources: ['osv'], software, ...extra });
const ITEM = { kind: 'application', name: 'gesdoc2', hostname: 'DESKTOP-MMMGL5M', osFamily: 'windows', organization: 'artemis-rd.com', minSeverity: 'MEDIUM' };

const application = buildItemNotification({
	item: ITEM,
	vulnerabilities: [
		vulnerability('CVE-2024-0001', 'CRITICAL', 9.8, [express], { sources: ['nvd', 'osv'] }),
		vulnerability('CVE-2024-29041', 'MEDIUM', 6.1, [express]),
		vulnerability('GHSA-qs', 'HIGH', 7.5, [qs]),
		vulnerability('PKSA-x', undefined, undefined, [qs])
	],
	packageFlags: new Map([['npm|express|4.17.1', { direct: true, dev: false }], ['npm|qs|6.7.0', { direct: false, dev: true }]])
});

describe('renderEmail', () => {
	const { subject, html, text } = renderEmail(application);

	it('says which item, how many and how bad in the subject', () => {
		assert.equal(subject, '[Ariane] gesdoc2 — application sur DESKTOP-MMMGL5M (Windows) : 4 nouvelles vulnérabilités, dont 1 critique');
	});

	it('names the machine item as a post, singular when one', () => {
		const machine = buildItemNotification({ item: { ...ITEM, kind: 'machine', name: 'web-01', osFamily: 'linux' }, vulnerabilities: [vulnerability('CVE-1', 'HIGH', 7, [{ name: 'openssl', version: '3.0.0' }])] });
		assert.equal(renderEmail(machine).subject, '[Ariane] web-01 — poste (Linux) : 1 nouvelle vulnérabilité, dont 1 haute');
	});

	it('shows the counts and one block per package with its tags, worst first', () => {
		assert.ok(html.indexOf('express') < html.indexOf('qs'));
		assert.match(html, /npm<\/span> <span[^>]*>directe<\/span>/);
		assert.match(html, /transitive<\/span> <span[^>]*>développement<\/span>/);
		assert.match(html, />Critique<\/span> <span[^>]*>1<\/span>/);
		assert.match(html, /border-top: 4px solid #b91c1c/); // color of the worst severity
	});

	it('lists each CVE with its link, labeled severity, score and sources', () => {
		assert.match(html, /<a href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/CVE-2024-0001"[^>]*>CVE-2024-0001<\/a>/);
		assert.match(html, /nvd \+ osv/);
		assert.match(html, />Non notée<\/span>/);
		assert.match(html, /https:\/\/packagist\.org\/security-advisories\/PKSA-x/);
	});

	it('names the organization and the threshold in the footer', () => {
		assert.match(html, /artemis-rd\.com · seuil d’alerte moyenne/);
	});

	it('gives a plain-text part with the same content', () => {
		assert.match(text, /^gesdoc2 — application sur DESKTOP-MMMGL5M \(Windows\)\n4 nouvelles vulnérabilités, dont 1 critique\nCritique 1 · Haute 1 · Moyenne 1 · Non notée 1/);
		assert.match(text, /express 4\.17\.1 \(npm, directe\)\n {4}CVE-2024-0001 {2}Critique 9\.8 {2}\[nvd\+osv\]\n {4}https:\/\/nvd\.nist\.gov/);
		assert.doesNotMatch(text, /</);
	});

	it('escapes every string coming from inventories', () => {
		const hostile = buildItemNotification({ item: { ...ITEM, name: '<script>x</script>' }, vulnerabilities: [vulnerability('CVE-1', 'HIGH', 7, [{ name: 'a"b<i>', version: "1'2", ecosystem: 'npm' }])] });
		const rendered = renderEmail(hostile).html;
		assert.doesNotMatch(rendered, /<script>|<i>/);
		assert.match(rendered, /&lt;script&gt;x&lt;\/script&gt;/);
		assert.match(rendered, /a&quot;b&lt;i&gt;/);
	});

	it('flags matches to verify and mentions the CVEs left out', () => {
		const program = { name: 'openssl', version: '3.0.0' };
		const many = Array.from({ length: 102 }, (_, index) => vulnerability(`CVE-2024-${String(index).padStart(4, '0')}`, 'LOW', 2, [program], { versionNormalized: index === 0 }));
		const rendered = renderEmail(buildItemNotification({ item: { ...ITEM, kind: 'machine' }, vulnerabilities: many }));
		assert.match(rendered.html, /à vérifier : correctif de distribution ou plateforme possible/);
		assert.match(rendered.html, /\+2 autre\(s\), moins graves/);
		assert.match(rendered.text, /\(à vérifier\)/);
	});
});
