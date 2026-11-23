import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { buildTransportOptions, sendVerificationEmail, buildAlertDigest } from '../utils/mailer.js';
import { validateConfig } from '../utils/config.js';

const SMTP = { MAIL_HOST: 'smtp.example.com', MAIL_PORT: '587', MAIL_USER: 'noreply@ariane.test', MAIL_PASS: 'x' };

describe('buildTransportOptions', () => {
	it('requires STARTTLS when implicit TLS is off', () => {
		const options = buildTransportOptions(SMTP);
		assert.equal(options.secure, false);
		assert.equal(options.requireTLS, true);
		assert.equal(options.port, 587);
	});

	it('uses implicit TLS when MAIL_SECURE=true', () => {
		const options = buildTransportOptions({ ...SMTP, MAIL_PORT: '465', MAIL_SECURE: 'true' });
		assert.equal(options.secure, true);
		assert.equal(options.requireTLS, false);
	});

	it('rejects an invalid MAIL_SECURE at start-up', () => {
		const { errors } = validateConfig({ ...SMTP, MAIL_SECURE: 'yes' });
		assert.ok(errors.some(error => /MAIL_SECURE/.test(error)));
	});
});

describe('sendVerificationEmail', () => {
	const previous = process.env.MAIL_FROM;
	afterEach(() => {
		if (previous === undefined) delete process.env.MAIL_FROM;
		else process.env.MAIL_FROM = previous;
	});

	it('sends from MAIL_FROM when set', async () => {
		process.env.MAIL_FROM = 'alerts@ariane.test';
		const info = await sendVerificationEmail('alice@ariane.test', '123456');
		const message = JSON.parse(info.message);
		assert.equal(message.from.address, 'alerts@ariane.test');
		assert.equal(message.to[0].address, 'alice@ariane.test');
	});
});

const vulnerability = cveID => ({ cveID, severity: 'HIGH', cvssScore: 7.5, software: [{ name: 'qs', version: '6.7.0', application: 'shop' }] });

describe('buildAlertDigest', () => {
	it('names the application of a vulnerable dependency', () => {
		const digest = { organization: 'Test', total: 1, shown: 1, machines: [{ hostname: 'web-01', vulnerabilities: [
			{ cveID: 'CVE-2024-29041', severity: 'MEDIUM', cvssScore: 6.1, software: [{ name: 'express', version: '4.17.1', ecosystem: 'npm', application: 'shop' }, { name: 'openssl', version: '3.0.0' }] }
		] }] };
		const { html } = buildAlertDigest(['admin@ariane.test'], digest);
		assert.ok(html.includes('express 4.17.1 (shop), openssl 3.0.0'), html);
	});

	it('links a CVE to the NVD and an advisory without CVE to OSV', () => {
		const { html } = buildAlertDigest(['admin@ariane.test'], { organization: 'Test', total: 2, shown: 2, machines: [{ hostname: 'web-01', vulnerabilities: [vulnerability('CVE-2024-29041'), vulnerability('GHSA-6rw7-vpxm-498p')] }] });
		assert.ok(html.includes('https://nvd.nist.gov/vuln/detail/CVE-2024-29041'));
		assert.ok(html.includes('https://osv.dev/vulnerability/GHSA-6rw7-vpxm-498p'));
		const packagist = buildAlertDigest(['admin@ariane.test'], { organization: 'Test', total: 1, shown: 1, machines: [{ hostname: 'web-01', vulnerabilities: [vulnerability('PKSA-wtxr-p26d-nn42')] }] });
		assert.ok(packagist.html.includes('https://packagist.org/security-advisories/PKSA-wtxr-p26d-nn42'));
	});
});
