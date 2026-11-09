import { createServer } from 'node:http';

// Local stand-in for Slack/Discord incoming webhooks: records each POSTed JSON body and answers
// `status` (204 by default). Point an organization at `${origin}/hook` with WEBHOOK_TEST_ORIGIN.
export async function startWebhookStub() {
	const posts = [];
	let status = 204;
	const server = createServer((request, response) => {
		let body = '';
		request.on('data', chunk => { body += chunk; });
		request.on('end', () => {
			posts.push({ path: request.url, body: JSON.parse(body) });
			response.writeHead(status).end();
		});
	});
	await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
	return {
		origin: `http://127.0.0.1:${server.address().port}`,
		posts,
		answer(code) { status = code; },
		reset() { posts.length = 0; status = 204; },
		close: () => new Promise(resolve => server.close(resolve))
	};
}
