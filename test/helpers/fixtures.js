import { mock } from 'node:test';
import pino from 'pino';
import express from 'express';
import database from '../../utils/database.js';
import logger from '../../utils/logger.js';
import { getTransporter } from '../../utils/mailer.js';
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
	return { status: response.status, body: json, text, headers: response.headers };
}

export async function createUser(baseUrl, local = 'alice', domain = ALLOWED_DOMAIN) {
	const username = `${local}@${domain}`;
	const response = await api(baseUrl, 'POST', '/auth/signup', { body: { username, password: PASSWORD, firstname: 'Test', lastname: 'User' } });
	if (response.status !== 200) throw new Error(`signup failed: ${response.status} ${response.text}`);
	return { username, userID: Number(response.body.user.userID) };
}

// Mails handed to the transport, newest last: the database only keeps a keyed hash of each
// verification code, so tests read the code from the mail sent at signup.
const outbox = [];
const transporter = getTransporter();
const deliver = transporter.sendMail.bind(transporter);
transporter.sendMail = options => {
	outbox.push(options);
	return deliver(options);
};

// The code of the latest verification mail sent to the user.
export async function getVerificationCode(userID) {
	const [user] = await database.query('SELECT username FROM users WHERE userID = ?', [userID]);
	const mail = outbox.findLast(({ to }) => to === user?.username);
	return mail?.html.match(/letter-spacing:6px[^>]*>(\d{6})</)?.[1];
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

export async function createSignedInUser(baseUrl, local = 'alice', domain = ALLOWED_DOMAIN) {
	const user = await createUser(baseUrl, local, domain);
	await verifyUser(baseUrl, user);
	return { ...user, ...(await signIn(baseUrl, user.username)) };
}

// A second organization owning `domainName`; returns its orgID.
export async function createOrganization(name, domainName) {
	const result = await database.query('INSERT INTO organizations (name, createdAt) VALUES (?, UTC_TIMESTAMP())', [name]);
	const orgID = Number(result.insertId);
	await database.query('INSERT INTO domain (domainName, orgID) VALUES (?, ?)', [domainName, orgID]);
	return orgID;
}

export async function setRole(userID, role) {
	await database.query('UPDATE users SET role = ? WHERE userID = ?', [role, userID]);
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
