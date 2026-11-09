import express from 'express';

const parseJson = express.json();

// express.json() with a 400 JSON answer on malformed bodies instead of the default HTML error.
export default function jsonBody(request, response, next) {
	parseJson(request, response, error => {
		if (error) return response.status(400).send({ message: 'Error : Bad JSON formatting.' });

		return next();
	});
}
