import authRouter from './routes/auth.js';
import logger from './utils/logger.js';
import pinoHttp from 'pino-http';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';

const app = express();
app.disable("x-powered-by");
const port = process.env.PORT;

//TODO : Security hardening with limiters, IP filters ect
//Why not using an Interceptor for that
app.use((request, response, next) => {
	express.json()(request, response, error => {
		if (error) return response.status(400).send({ message: 'Error : Bad JSON formatting.' });

		return next();
	});
});

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
app.use('/auth', cors(), authRouter);

app.listen(port, () => { logger.info(`Server running on http://localhost:${port}`); });
