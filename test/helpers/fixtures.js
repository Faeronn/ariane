import { mock } from 'node:test';
import pino from 'pino';
import express from 'express';
import database from '../../utils/database.js';
import logger from '../../utils/logger.js';
import { ALLOWED_DOMAIN } from './database.js';

export const PASSWORD = process.env.TEST_USER_SECRET ?? 'Sup3r-secret';

export async function api(baseUrl, method, path, { body, token, headers = {} } = {}) {
	const response = await fetch(`${baseUrl}${path}`, {
		method,
		headers: {
			...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
			...(token ? { Authorization: `Bearer ${token}` } : {}),
			...headers
		},
		body: body === undefined || typeof body === 'string' ? body : JSON.stringify(body)
	});
	const text = await response.text();
	let json;
	try {
		json = JSON.parse(text);
	} catch {
		json = undefined;
	}
	return { status: response.status, body: json, text };
}

export async function createUser(baseUrl, local = 'alice') {
	const username = `${local}@${ALLOWED_DOMAIN}`;
	const response = await api(baseUrl, 'POST', '/auth/signup', { body: { username, password: PASSWORD, firstname: 'Test', lastname: 'User' } });
	if (response.status !== 200) throw new Error(`signup failed: ${response.status} ${response.text}`);
	return { username, userID: Number(response.body.user.userID) };
}

export async function getVerificationCode(userID) {
	const rows = await database.query('SELECT verificationCode FROM verifications WHERE userID = ?', [userID]);
	return rows[0]?.verificationCode;
}

export async function verifyUser(baseUrl, user) {
	const code = await getVerificationCode(user.userID);
	const response = await api(baseUrl, 'GET', `/auth/verify?username=${encodeURIComponent(user.username)}&code=${code}`);
	if (response.status !== 200) throw new Error(`verify failed: ${response.status} ${response.text}`);
}

export async function signIn(baseUrl, username, password = PASSWORD) {
	const response = await api(baseUrl, 'POST', '/auth/signin', { body: { username, password } });
	if (response.status !== 200) throw new Error(`signin failed: ${response.status} ${response.text}`);
	return { accessToken: response.body.accesstoken, refreshToken: response.body.refreshToken };
}

export async function createSignedInUser(baseUrl, local = 'alice') {
	const user = await createUser(baseUrl, local);
	await verifyUser(baseUrl, user);
	return { ...user, ...(await signIn(baseUrl, user.username)) };
}

export async function countRows(table) {
	const [row] = await database.query(`SELECT COUNT(*) AS n FROM \`${table}\``);
	return Number(row.n);
}

// Capture (and mute) every log line written through the app logger and its children until restore().
export function captureLogs() {
	const lines = [];
	const stream = logger[pino.symbols.streamSym];
	const writeMock = mock.method(stream, 'write', chunk => {
		lines.push(JSON.parse(chunk));
		return true;
	});
	return { lines, restore: () => writeMock.mock.restore() };
}

// Listen on an ephemeral port with a throwaway Express app built by `configure`; returns { baseUrl, close }.
export async function startThrowawayApp(configure) {
	const app = express();
	app.disable('x-powered-by');
	configure(app);
	const server = await new Promise(resolve => { const listening = app.listen(0, () => resolve(listening)); });
	return {
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		close: () => new Promise(resolve => server.close(resolve))
	};
}
