import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildItemNotification, MAX_LISTED, versionToShow } from '../utils/notification.js';
import { vulnerabilityLink } from '../utils/vulnerability-link.js';

const ITEM = { kind: 'application', name: 'shop', hostname: 'web-01', osFamily: 'linux', organization: 'Test', minSeverity: 'MEDIUM' };
const express = { name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'shop' };
const qs = { name: 'qs', version: '6.7.0', ecosystem: 'npm', application: 'shop' };
const vulnerability = (cveID, severity, cvssScore, software, extra = {}) => ({ cveID, severity, cvssScore, sources: ['osv'], software, ...extra });

describe('buildItemNotification', () => {
	const notification = buildItemNotification({
		item: ITEM,
		vulnerabilities: [
			vulnerability('CVE-2024-0002', 'MEDIUM', 6.1, [express]),
			vulnerability('GHSA-qs', 'HIGH', 7.5, [qs]),
			vulnerability('CVE-2024-0001', 'CRITICAL', 9.8, [express], { sources: ['nvd', 'osv'] }),
			vulnerability('PKSA-x', undefined, undefined, [qs])
		],
		packageFlags: new Map([['npm|express|4.17.1', { direct: true, dev: false }], ['npm|qs|6.7.0', { direct: false, dev: false }]])
	});

	it('counts the item CVEs per severity, unscored apart', () => {
		assert.deepEqual(notification.counts, { total: 4, bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 0, UNSCORED: 1 } });
		assert.equal(notification.worst, 'CRITICAL');
		assert.equal(notification.hidden, 0);
	});

	it('groups the CVEs per package, worst group first, worst CVE first, unscored last', () => {
		assert.deepEqual(notification.groups.map(({ software, worst, vulnerabilities }) => `${software.name}:${worst}:${vulnerabilities.map(({ id }) => id).join(',')}`), [
			'express:CRITICAL:CVE-2024-0001,CVE-2024-0002',
			'qs:HIGH:GHSA-qs,PKSA-x'
		]);
	});

	it('keeps package flags, sources and links', () => {
		const [first] = notification.groups;
		assert.deepEqual(first.software, { name: 'express', version: '4.17.1', ecosystem: 'npm', direct: true, dev: false });
		assert.deepEqual(first.vulnerabilities[0].sources, ['nvd', 'osv']);
		assert.equal(first.vulnerabilities[0].link, 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001');
	});

	it('lists one CVE under each software of the item it affects, counted once', () => {
		const shared = buildItemNotification({ item: { ...ITEM, kind: 'machine' }, vulnerabilities: [vulnerability('CVE-1', 'HIGH', 7, [{ name: 'openssl', version: '3.0.0' }, { name: 'libssl3', version: '3.0.0' }], { versionNormalized: true })] });
		assert.equal(shared.counts.total, 1);
		assert.equal(shared.groups.length, 2);
		assert.equal(shared.groups[0].vulnerabilities[0].toVerify, true);
	});

	it(`lists at most ${MAX_LISTED} CVEs, the worst ones, and counts the rest`, () => {
		const many = Array.from({ length: 150 }, (_, index) => vulnerability(`CVE-2024-${String(index).padStart(4, '0')}`, index < 10 ? 'CRITICAL' : 'LOW', index < 10 ? 9 : 2, [express]));
		const big = buildItemNotification({ item: ITEM, vulnerabilities: many });
		assert.equal(big.counts.total, 150);
		assert.equal(big.hidden, 50);
		assert.equal(big.groups[0].vulnerabilities.length, MAX_LISTED);
		assert.equal(big.groups[0].vulnerabilities[0].severity, 'CRITICAL');
	});
});

describe('versionToShow', () => {
	it('drops a version the display name already holds', () => {
		assert.equal(versionToShow({ name: '7-zip 19.00 (x64)', version: '19.00' }), '');
		assert.equal(versionToShow({ name: 'openssl', version: '3.0.0' }), '3.0.0');
	});
});

describe('vulnerabilityLink', () => {
	it('links a CVE to the NVD, a Packagist advisory to Packagist, any other id to OSV', () => {
		assert.equal(vulnerabilityLink('CVE-2024-29041'), 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041');
		assert.equal(vulnerabilityLink('PKSA-wtxr-p26d-nn42'), 'https://packagist.org/security-advisories/PKSA-wtxr-p26d-nn42');
		assert.equal(vulnerabilityLink('GHSA-6rw7-vpxm-498p'), 'https://osv.dev/vulnerability/GHSA-6rw7-vpxm-498p');
	});
});
