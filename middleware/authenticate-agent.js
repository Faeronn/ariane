import database from '../utils/database.js';
import { hashToken } from '../utils/jwt.js';

// Requires `X-Agent-Key` of an enrolled, non-revoked machine; sets request.machine.
export default async function authenticateAgent(request, response, next) {
	const apiKey = request.get('x-agent-key');
	if (!apiKey) return response.status(401).send({ message: 'Error : Invalid agent key.' });

	const machines = await database.query('SELECT machineID, hostname FROM machines WHERE apiKeyHash = ? AND revokedAt IS NULL', [hashToken(apiKey)]);
	if (machines.length === 0) return response.status(401).send({ message: 'Error : Invalid agent key.' });

	request.machine = machines[0];
	return next();
}
