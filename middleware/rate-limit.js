import { rateLimit, ipKeyGenerator, MemoryStore } from 'express-rate-limit';

const MINUTE = 60_000;
const TOO_MANY = { message: 'Error : Too many requests.' };

// In-memory stores: limits hold per API instance (see the integration memory).
const stores = [];

export const byIp = request => ipKeyGenerator(request.ip);

// A limiter answering the API's JSON contract, with draft-7 RateLimit headers and Retry-After.
export function createRateLimit({ windowMs, limit, keyGenerator = byIp }) {
	const store = new MemoryStore();
	stores.push(store);
	return rateLimit({
		store,
		windowMs,
		limit,
		keyGenerator,
		standardHeaders: 'draft-7',
		legacyHeaders: false,
		handler: (request, response) => response.status(429).send(TOO_MANY)
	});
}

// Tests start every case unblocked.
export async function resetRateLimits() {
	await Promise.all(stores.map(store => store.resetAll()));
}

const signinUsername = request => (typeof request.body?.username === 'string' ? request.body.username.trim().toLowerCase() : '');

// Brute force on one account, then on many accounts from one address.
export const signinPerAccount = createRateLimit({ windowMs: 15 * MINUTE, limit: 10, keyGenerator: request => `${byIp(request)}|${signinUsername(request)}` });
export const signinPerIp = createRateLimit({ windowMs: 15 * MINUTE, limit: 50 });
export const signupPerIp = createRateLimit({ windowMs: 60 * MINUTE, limit: 5 });
export const verifyPerIp = createRateLimit({ windowMs: 15 * MINUTE, limit: 10 });
export const refreshPerIp = createRateLimit({ windowMs: 15 * MINUTE, limit: 30 });

// A looping or stolen agent key cannot flood ingestion; keyed by the authenticated machine.
export const inventoryPerMachine = createRateLimit({ windowMs: 60 * MINUTE, limit: 30, keyGenerator: request => `machine:${request.machine.machineID}` });
// One call per application: a machine hosting many applications sends many per scan.
export const applicationsPerMachine = createRateLimit({ windowMs: 60 * MINUTE, limit: 120, keyGenerator: request => `applications:${request.machine.machineID}` });

// Last line against floods on any route, mounted before everything else.
export const globalPerIp = createRateLimit({ windowMs: 15 * MINUTE, limit: 600 });
