import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

// Real answer (2026-11-23) for symfony/mime, symfony/http-foundation and phpoffice/phpword.
const loadAdvisories = () => JSON.parse(readFileSync(new URL('../fixtures/packagist/advisories.json', import.meta.url), 'utf8')).advisories;

const send = (response, status, body) => response.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));

// Local stand-in for Packagist's security advisories API: answers the requested package names from
// the fixture; can be scripted to fail (`failNext(status, times)`) or hang (`hangNext(times)`).
export async function startPackagistStub() {
	let advisories = loadAdvisories();
	const requests = [];
	let failures = [];
	let hangs = 0;

	const server = createServer((request, response) => {
		let raw = '';
		request.on('data', chunk => { raw += chunk; });
		request.on('end', () => {
			const names = new URLSearchParams(raw).getAll('packages[]');
			requests.push({ method: request.method, path: request.url, names });
			if (hangs > 0) {
				hangs -= 1;
				return; // never answer: the client must time out
			}
			if (failures.length > 0) return send(response, failures.shift(), { message: 'stub failure' });
			if (request.method !== 'POST' || request.url !== '/api/security-advisories/') return send(response, 404, {});
			return send(response, 200, { advisories: Object.fromEntries(names.filter(name => advisories[name]?.length > 0).map(name => [name, advisories[name]])) });
		});
	});
	await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

	return {
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		requests,
		setAdvisories(name, list) { advisories[name] = list; },
		failNext(status, times = 1) { failures = [...failures, ...Array.from({ length: times }, () => status)]; },
		hangNext(times = 1) { hangs += times; },
		reset() {
			advisories = loadAdvisories();
			requests.length = 0;
			failures = [];
			hangs = 0;
		},
		close: () => new Promise(resolve => {
			server.closeAllConnections();
			server.close(resolve);
		})
	};
}
