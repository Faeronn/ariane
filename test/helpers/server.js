import database from '../../utils/database.js';
import app from '../../app.js';

// Start the app on an ephemeral port. Call close() in the suite's after hook.
export async function startServer() {
	const server = await new Promise((resolve, reject) => {
		const listening = app.listen(0, error => (error ? reject(error) : resolve(listening)));
	});

	return {
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		async close() {
			await new Promise(resolve => server.close(resolve));
			await database.end();
		}
	};
}
