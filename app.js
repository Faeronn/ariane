import errorHandler from './middleware/error-handler.js';
import corsAllowlist from './middleware/cors.js';
import { globalPerIp } from './middleware/rate-limit.js';
import notFound from './middleware/not-found.js';
import jsonBody, { createJsonBody } from './middleware/json-body.js';
import machinesRouter from './routes/machines.js';
import agentsRouter from './routes/agents.js';
import usersRouter from './routes/users.js';
import softwareRouter from './routes/software.js';
import authRouter from './routes/auth.js';
import { startResolveCpeJob } from './jobs/resolve-cpe.js';
import { startSyncCvesJob } from './jobs/sync-cves.js';
import { startPurgeJob } from './jobs/purge.js';
import { validateConfig } from './utils/config.js';
import logger from './utils/logger.js';
import database from './utils/database.js';
import pinoHttp from 'pino-http';
import crypto from 'node:crypto';
import express from 'express';

const app = express();
app.disable("x-powered-by");
const port = process.env.PORT;

// Behind a reverse proxy, TRUST_PROXY hops make request.ip (used by the rate limits) the client's.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY));
app.use(globalPerIp);

// Inventories outgrow the default 100 kb; the parsed body is then skipped by the global parser.
app.use('/agents', createJsonBody({ limit: '5mb' }));
app.use(jsonBody);

app.use(
	pinoHttp({
		logger,
		genReqId: (request) => request.headers['x-request-id'] || crypto.randomUUID(),
		customLogLevel: (request, response, error) => {
			if (error || response.statusCode >= 500) return 'error';
			if (response.statusCode >= 400) return 'warn';
			return 'info';
		},
		serializers: {
			req(request) { return { id: request.id, method: request.method, url: request.url, remoteAddress: request.socket?.remoteAddress }; },
			res(response) { return { statusCode: response.statusCode }; }
		},
	})
);

// Routes
app.use('/auth', corsAllowlist, authRouter);
app.use('/machines', corsAllowlist, machinesRouter);
app.use('/users', corsAllowlist, usersRouter);
app.use('/software', corsAllowlist, softwareRouter);
app.use('/agents', agentsRouter);

app.use(notFound);
app.use(errorHandler);

async function start() {
	const { errors, warnings } = validateConfig();
	for (const warning of warnings) logger.warn(warning);
	if (errors.length > 0) {
		for (const error of errors) logger.error(error);
		logger.error('Invalid configuration, see .env.example. Server not started.');
		process.exitCode = 1;
		await database.end(); // the pool would otherwise keep the process alive
		return;
	}

	app.listen(port, () => {
		logger.info(`Server running on http://localhost:${port}`);
		startPurgeJob();
		// Background NVD work, off the request path. NVD_ENABLED=false turns it off (tests, offline dev).
		if (process.env.NVD_ENABLED !== 'false') {
			startResolveCpeJob();
			startSyncCvesJob();
		}
	});
}

if (import.meta.main) await start();

export default app;

