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
	// One HTTP exchange; a network failure or timeout becomes { error }.
	function send(method, path, body) {
		return fetch(`${baseUrl}${path}`, {
			method,
			headers: body ? { 'Content-Type': 'application/json' } : {},
			body: body ? JSON.stringify(body) : undefined,
			signal: AbortSignal.timeout(timeoutMs)
		}).then(response => ({ response }), error => ({ error }));
	}

	// `missing`: what a 404 resolves to when the caller accepts an absent resource.
	async function request(method, path, body, { missing } = {}) {
		for (let attempt = 0; ; attempt += 1) {
			const { response, error } = await send(method, path, body);
			if (response?.ok) return response.json();
			if (response?.status === 404 && missing !== undefined) return missing;
			const retryable = error || RETRYABLE(response.status);
			if (!retryable || attempt >= retries) {
				throw new OsvError(error ? `OSV request failed: ${error.message}` : `OSV answered ${response.status} for ${path}`, error ? { cause: error } : undefined);
			}
			await sleep(backoffMs * 2 ** attempt);
		}
	}

	// Remaining pages of one package's vulnerabilities (querybatch pages per query).
	async function remainingIds(item, pageToken) {
		const found = [];
		for (let token = pageToken; token;) {
			const page = await request('POST', '/v1/query', { ...toQuery(item), page_token: token });
			found.push(...(page.vulns ?? []).map(({ id, modified }) => ({ id, modified })));
			token = page.next_page_token;
		}
		return found;
	}

	return {
		// Vulnerabilities affecting each package version, in the order of `packages`, as
		// [{ id, modified }]: `modified` tells when a stored record is out of date.
		async queryBatch(packages) {
			const results = [];
			for (let start = 0; start < packages.length; start += MAX_BATCH) {
				const chunk = packages.slice(start, start + MAX_BATCH);
				const page = await request('POST', '/v1/querybatch', { queries: chunk.map(item => toQuery(item)) });
				for (const [index, item] of chunk.entries()) {
					const result = page.results?.[index] ?? {};
					const found = (result.vulns ?? []).map(({ id, modified }) => ({ id, modified }));
					if (result.next_page_token) found.push(...await remainingIds(item, result.next_page_token));
					results.push(found);
				}
			}
			return results;
		},
		// Full OSV record of one vulnerability (aliases, severity vectors, summary, dates); false when
		// OSV no longer has it (a withdrawn or renamed advisory).
		vuln: id => request('GET', `/v1/vulns/${encodeURIComponent(id)}`, undefined, { missing: false })
	};
}

let defaultClient;
// The client configured from OSV_BASE_URL, created on first use.
export function getOsvClient() {
	defaultClient ??= createOsvClient({ baseUrl: process.env.OSV_BASE_URL || DEFAULT_BASE_URL });
	return defaultClient;
}
