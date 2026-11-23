import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';

export const loadOsvFixture = name => JSON.parse(readFileSync(new URL(`../fixtures/osv/${name}`, import.meta.url), 'utf8'));

// Real querybatch answer (2026-11-23) for these three package versions, in this order.
const REAL_BATCH_PACKAGES = ['npm:express@4.17.1', 'Packagist:symfony/http-kernel@5.4.0', 'PyPI:requests@2.25.0'];

const send = (response, status, body) => response.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(body));

// querybatch answer: per query, its ids as `vulns` with the record's `modified`, or an empty
// object when none.
function batchResults(ids, vulns, queries) {
	return queries.map(({ package: { ecosystem, name }, version }) => {
		const found = ids.get(`${ecosystem}:${name}@${version}`) ?? [];
		return found.length > 0 ? { vulns: found.map(id => ({ id, modified: vulns.get(id)?.modified ?? '2026-11-01T00:00:00Z' })) } : {};
	});
}

// Local stand-in for the OSV API: answers querybatch from per-package id lists and vulns/<id> from
// fixtures; can be scripted to fail (`failNext(status, times)`) or hang (`hangNext(times)`).
export async function startOsvStub() {
	const ids = new Map();
	const vulns = new Map();
	const requests = [];
	let failures = [];
	let hangs = 0;

	const seed = () => {
		const batch = loadOsvFixture('querybatch.json');
		for (const [index, key] of REAL_BATCH_PACKAGES.entries()) ids.set(key, (batch.results[index].vulns ?? []).map(({ id }) => id));
		for (const id of ['GHSA-rv95-896h-c2vc', 'GHSA-qw6h-vgh9-j6wx', 'PYSEC-2023-74']) vulns.set(id, loadOsvFixture(`vuln-${id}.json`));
	};
	seed();

	const server = createServer((request, response) => {
		let raw = '';
		request.on('data', chunk => { raw += chunk; });
		request.on('end', () => {
			const body = raw ? JSON.parse(raw) : undefined;
			requests.push({ method: request.method, path: request.url, body });
			if (hangs > 0) {
				hangs -= 1;
				return; // never answer: the client must time out
			}
			if (failures.length > 0) return send(response, failures.shift(), { message: 'stub failure' });

			if (request.method === 'POST' && request.url === '/v1/querybatch') return send(response, 200, { results: batchResults(ids, vulns, body.queries) });
			const vulnId = decodeURIComponent(request.url.replace(/^\/v1\/vulns\//, ''));
			if (request.method === 'GET' && vulns.has(vulnId)) return send(response, 200, vulns.get(vulnId));
			return send(response, 404, { code: 5, message: 'Bug not found.' });
		});
	});
	await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

	return {
		baseUrl: `http://127.0.0.1:${server.address().port}`,
		requests,
		// Vulnerability ids for `ecosystem:name@version`, and the record served for an id.
		setIds(key, list) { ids.set(key, list); },
		setVuln(record) { vulns.set(record.id, record); },
		failNext(status, times = 1) { failures = [...failures, ...Array.from({ length: times }, () => status)]; },
		hangNext(times = 1) { hangs += times; },
		reset() {
			ids.clear();
			vulns.clear();
			seed();
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
