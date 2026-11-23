// OSV.dev API client (https://google.github.io/osv.dev/api/): known vulnerabilities of exact
// package versions, per ecosystem (`npm`, `Packagist`, `PyPI`). No key, no published rate limit.
const DEFAULT_BASE_URL = 'https://api.osv.dev';
// querybatch accepts at most 1000 queries per request.
const MAX_BATCH = 1000;
const RETRYABLE = status => status === 429 || status >= 500;

export class OsvError extends Error {
	constructor(message, options) {
		super(message, options);
		this.name = 'OsvError';
	}
}

const toQuery = ({ ecosystem, name, version }) => ({ package: { ecosystem, name }, version });

const sleep = milliseconds => new Promise(resolve => { setTimeout(resolve, milliseconds); });

export function createOsvClient({ baseUrl = DEFAULT_BASE_URL, timeoutMs = 30_000, retries = 3, backoffMs = 2000 } = {}) {
	async function request(method, path, body) {
		for (let attempt = 0; ; attempt += 1) {
			let response;
			try {
				response = await fetch(`${baseUrl}${path}`, {
					method,
					headers: body ? { 'Content-Type': 'application/json' } : {},
					body: body ? JSON.stringify(body) : undefined,
					signal: AbortSignal.timeout(timeoutMs)
				});
			} catch (error) {
				if (attempt >= retries) throw new OsvError(`OSV request failed: ${error.message}`, { cause: error });
				await sleep(backoffMs * 2 ** attempt);
				continue;
			}
			if (response.ok) return response.json();
			if (!RETRYABLE(response.status) || attempt >= retries) throw new OsvError(`OSV answered ${response.status} for ${path}`);
			await sleep(backoffMs * 2 ** attempt);
		}
	}

	// Remaining pages of one package's vulnerability ids (querybatch pages per query).
	async function remainingIds(item, pageToken) {
		const ids = [];
		for (let token = pageToken; token;) {
			const page = await request('POST', '/v1/query', { ...toQuery(item), page_token: token });
			ids.push(...(page.vulns ?? []).map(({ id }) => id));
			token = page.next_page_token;
		}
		return ids;
	}

	return {
		// Vulnerability ids affecting each package version, in the order of `packages`.
		async queryBatch(packages) {
			const results = [];
			for (let start = 0; start < packages.length; start += MAX_BATCH) {
				const chunk = packages.slice(start, start + MAX_BATCH);
				const page = await request('POST', '/v1/querybatch', { queries: chunk.map(item => toQuery(item)) });
				for (const [index, item] of chunk.entries()) {
					const result = page.results?.[index] ?? {};
					const ids = (result.vulns ?? []).map(({ id }) => id);
					if (result.next_page_token) ids.push(...await remainingIds(item, result.next_page_token));
					results.push(ids);
				}
			}
			return results;
		},
		// Full OSV record of one vulnerability (aliases, severity vectors, summary, dates).
		vuln: id => request('GET', `/v1/vulns/${encodeURIComponent(id)}`)
	};
}

let defaultClient;
// The client configured from OSV_BASE_URL, created on first use.
export function getOsvClient() {
	defaultClient ??= createOsvClient({ baseUrl: process.env.OSV_BASE_URL || DEFAULT_BASE_URL });
	return defaultClient;
}
