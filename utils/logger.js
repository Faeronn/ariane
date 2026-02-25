import pino from 'pino';

const isProduction = process.env.NODE_ENV === 'production';

const logger = pino({
	level: process.env.LOG_LEVEL || (isProduction ? 'info' : 'debug'),
	redact: { paths: [ 'req.headers.authorization', 'req.headers.cookie', 'req.body.password', 'req.body.refreshToken'], remove: true },
	transport: isProduction ? undefined : { target: 'pino-pretty', options: { colorize: true, singleLine: true, translateTime: 'SYS:standard', }},
});

export default logger;