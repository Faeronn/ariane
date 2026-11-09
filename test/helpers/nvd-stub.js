import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

export const loadFixture = name => JSON.parse(readFileSync(new URL(`../fixtures/nvd/${name}`, import.meta.url), 'utf8'));

// Local stand-in for the NVD API: serves fixtures by path + query, paginates their item arrays,
// and can be scripted to fail (`failNext(status, times)`) or hang (`hangNext(times)`).
export async function startNvdStub() {
	const routes = new Map();
	const requests = [];
	let failures = [];
	let hangs = 0;

	const server = createServer((request, response) => {
		const [pathname, search = ''] = request.url.split('?');
		const url = { pathname, searchParams: new URLSearchParams(search) };
		requests.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), headers: request.headers });

		if (hangs > 0) {
			hangs -= 1;
			return; // never answer: the client must time out
		}
		if (failures.length > 0) {
			const status = failures.shift();
			response.writeHead(status, { 'Content-Type': 'text/plain' }).end('stub failure');
			return;
		}

		const key = url.searchParams.get('keywordSearch') ?? url.searchParams.get('cpeName');
		const fixture = routes.get(`${url.pathname} ${key}`) ?? { resultsPerPage: 0, startIndex: 0, totalResults: 0, products: [], vulnerabilities: [] };
		const itemsKey = url.pathname.startsWith('/cpes') ? 'products' : 'vulnerabilities';
		const startIndex = Number(url.searchParams.get('startIndex') ?? 0);
		const pageSize = Number(url.searchParams.get('resultsPerPage') ?? 2000);
		const items = (fixture[itemsKey] ?? []).slice(startIndex, startIndex + pageSize);
		const body = { ...fixture, startIndex, resultsPerPage: items.length, totalResults: (fixture[itemsKey] ?? []).length, [itemsKey]: items };
		response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));
	});
	await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

	return {
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		requests,
		// Serve `fixture` for a keywordSearch (CPE API) or a cpeName (CVE API).
		route(path, key, fixture) { routes.set(`${path} ${key}`, fixture); },
		failNext(status, times = 1) { failures = [...failures, ...Array.from({ length: times }, () => status)]; },
		hangNext(times = 1) { hangs += times; },
		reset() {
			routes.clear();
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
