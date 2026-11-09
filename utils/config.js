import { parseOrigins, isValidOrigin } from '../middleware/cors.js';

// Boot-time checks of the environment: a configuration that cannot work stops the start-up
// instead of failing later on a request. Pure over an env object; app.js decides what to do.

const REQUIRED = ['PORT', 'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET'];
const MAIL_REQUIRED = ['MAIL_HOST', 'MAIL_PORT', 'MAIL_USER', 'MAIL_PASS'];

const isSet = (environment, name) => Boolean(environment[name]?.trim());

function checkRequired(environment, report) {
	for (const name of REQUIRED.filter(variable => !isSet(environment, variable))) report.errors.push(`${name} is not set.`);
}

function checkMail(environment, report) {
	if (environment.MAIL_TRANSPORT === 'json') {
		if (environment.NODE_ENV === 'production') report.errors.push('MAIL_TRANSPORT=json is not allowed in production: verification mails would never be sent.');
		return;
	}
	for (const name of MAIL_REQUIRED.filter(variable => !isSet(environment, variable))) report.errors.push(`${name} is not set (or set MAIL_TRANSPORT=json outside production).`);
	if (isSet(environment, 'MAIL_SECURE') && !['true', 'false'].includes(environment.MAIL_SECURE)) report.errors.push('MAIL_SECURE must be true (implicit TLS, port 465) or false (STARTTLS required).');
}

function checkNvd(environment, report) {
	if (environment.NVD_ENABLED === 'false' || isSet(environment, 'NVD_API_KEY')) return;
	report.warnings.push('NVD_API_KEY is not set: NVD allows only 5 requests per 30 s, CPE and CVE resolution will be slow. Free key: https://nvd.nist.gov/developers/request-an-api-key');
}

function checkCors(environment, report) {
	for (const origin of parseOrigins(environment.CORS_ORIGINS).filter(value => !isValidOrigin(value))) report.errors.push(`CORS_ORIGINS: "${origin}" is not an origin like https://dashboard.example.com (no path, no trailing slash).`);
}

function checkTrustProxy(environment, report) {
	if (isSet(environment, 'TRUST_PROXY') && !/^\d+$/.test(environment.TRUST_PROXY)) report.errors.push('TRUST_PROXY must be the number of reverse proxies in front of the API (0 or empty when none).');
}

function checkRetention(environment, report) {
	if (isSet(environment, 'SNAPSHOT_RETENTION_DAYS') && !/^[1-9]\d*$/.test(environment.SNAPSHOT_RETENTION_DAYS)) report.errors.push('SNAPSHOT_RETENTION_DAYS must be a whole number of days (1 or more).');
}

const RULES = [checkRequired, checkMail, checkNvd, checkCors, checkTrustProxy, checkRetention];

export function validateConfig(environment = process.env) {
	const report = { errors: [], warnings: [] };
	for (const rule of RULES) rule(environment, report);
	return report;
}
