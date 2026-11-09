import logger from '../utils/logger.js';

// Last-resort handler for errors no route caught: log them, never leak details to the client.
// eslint-disable-next-line no-unused-vars -- Express recognizes error handlers by their 4 parameters
export default function errorHandler(error, request, response, next) {
	(request.log ?? logger).error(error);
	if (response.headersSent) return response.end();

	return response.status(500).send({ message: 'Error : Internal server error.' });
}
