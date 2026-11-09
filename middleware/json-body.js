import express from 'express';

// express.json() with JSON answers instead of the default HTML errors:
// 413 when the body exceeds `options.limit`, 400 when it is malformed.
export function createJsonBody(options) {
	const parseJson = express.json(options);

	return function jsonBody(request, response, next) {
		parseJson(request, response, error => {
			if (error?.type === 'entity.too.large') return response.status(413).send({ message: 'Error : Payload too large.' });
			if (error) return response.status(400).send({ message: 'Error : Bad JSON formatting.' });

			return next();
		});
	};
}

export default createJsonBody();
