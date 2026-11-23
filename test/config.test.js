import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { validateConfig } from '../utils/config.js';

const PRODUCTION = {
	NODE_ENV: 'production', PORT: '3000',
	DB_HOST: 'localhost', DB_PORT: '3306', DB_USER: 'ariane', DB_PASSWORD: randomUUID(), DB_NAME: 'ariane',
	JWT_ACCESS_SECRET: 'a', JWT_REFRESH_SECRET: 'b',
	MAIL_HOST: 'smtp.example.com', MAIL_PORT: '587', MAIL_USER: 'user', MAIL_PASS: randomUUID(),
	NVD_API_KEY: 'key'
};
const without = (name, base = PRODUCTION) => Object.fromEntries(Object.entries(base).filter(([key]) => key !== name));

describe('validateConfig', () => {
	it('accepts a complete production configuration without warning', () => {
		assert.deepEqual(validateConfig(PRODUCTION), { errors: [], warnings: [] });
	});

	for (const name of ['DB_NAME', 'JWT_ACCESS_SECRET', 'PORT']) {
		it(`reports a missing ${name}`, () => {
			const { errors } = validateConfig(without(name));
			assert.equal(errors.length, 1);
			assert.match(errors[0], new RegExp(name));
		});
	}

	it('treats a blank value as missing', () => {
		assert.match(validateConfig({ ...PRODUCTION, DB_USER: '  ' }).errors[0], /DB_USER/);
	});

	it('requires the SMTP settings unless the JSON transport is used', () => {
		const { errors } = validateConfig(without('MAIL_HOST'));
		assert.equal(errors.length, 1);
		assert.match(errors[0], /MAIL_HOST/);
		assert.deepEqual(validateConfig({ ...without('MAIL_HOST'), NODE_ENV: 'development', MAIL_TRANSPORT: 'json' }).errors, []);
	});

	it('refuses the JSON mail transport in production', () => {
		const { errors } = validateConfig({ ...PRODUCTION, MAIL_TRANSPORT: 'json' });
		assert.equal(errors.length, 1);
		assert.match(errors[0], /MAIL_TRANSPORT=json/);
	});

	it('warns about an unknown NODE_ENV and still accepts the configuration', () => {
		const { errors, warnings } = validateConfig({ ...PRODUCTION, NODE_ENV: 'prod' });
		assert.deepEqual(errors, []);
		assert.equal(warnings.length, 1);
		assert.match(warnings[0], /NODE_ENV="prod" is not production, development or test/);
		assert.deepEqual(validateConfig({ ...PRODUCTION, NODE_ENV: 'development' }).warnings, []);
	});

	it('refuses an OSV_BASE_URL that is not an http(s) URL', () => {
		assert.deepEqual(validateConfig({ ...PRODUCTION, OSV_BASE_URL: 'http://127.0.0.1:8080' }).errors, []);
		assert.match(validateConfig({ ...PRODUCTION, OSV_BASE_URL: 'api.osv.dev' }).errors[0], /OSV_BASE_URL must be an http\(s\) URL/);
	});

	it('warns about the NVD rate limit when jobs run without a key', () => {
		const { errors, warnings } = validateConfig(without('NVD_API_KEY'));
		assert.deepEqual(errors, []);
		assert.equal(warnings.length, 1);
		assert.match(warnings[0], /5 requests per 30 s/);
		assert.deepEqual(validateConfig({ ...without('NVD_API_KEY'), NVD_ENABLED: 'false' }).warnings, []);
	});
});

describe('app start-up', () => {
	it('exits with code 1 and names the missing variables', () => {
		const environment = { ...process.env, MAIL_TRANSPORT: '', MAIL_HOST: '', MAIL_PORT: '', MAIL_USER: '', MAIL_PASS: '', PORT: '0', LOG_LEVEL: 'error' };
		const result = spawnSync(process.execPath, ['app.js'], { env: environment, encoding: 'utf8', timeout: 20_000 });
		assert.equal(result.status, 1);
		assert.match(result.stdout, /MAIL_HOST is not set/);
		assert.match(result.stdout, /Server not started/);
	});
});
