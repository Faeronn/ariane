// Fallback for unknown routes: answer the JSON contract instead of Express's default HTML page.
export default function notFound(request, response) {
	return response.status(404).send({ message: 'Error : Not found.' });
}
