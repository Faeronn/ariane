import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { buildTransportOptions, sendVerificationEmail } from '../utils/mailer.js';
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
