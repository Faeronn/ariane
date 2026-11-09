import database from '../../utils/database.js';
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
	const response = await api(baseUrl, 'POST', `/auth/verify/${code}`);
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
