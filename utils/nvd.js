// NVD API 2.0 client. Limits (https://nvd.nist.gov/developers/start-here): 5 requests per rolling
// 30 s window without a key, 50 with an `apiKey` header; at most 2000 results per page.
const DEFAULT_BASE_URL = 'https://services.nvd.nist.gov/rest/json';
const WINDOW_MS = 30_000;
const MAX_PAGE_SIZE = 2000;
const RETRYABLE_STATUSES = new Set([403, 429, 503]);

export class NvdError extends Error {
	constructor(message, options) {
		super(message, options);
		this.name = 'NvdError';
	}
}

const sleep = milliseconds => new Promise(resolve => { setTimeout(resolve, milliseconds); });

// Sliding window: never more than `maxRequests` started within any `windowMs`.
function createLimiter(maxRequests, windowMs) {
	const startedAt = [];
	let queue = Promise.resolve();

	return function acquire() {
		const turn = queue.then(async () => {
			while (startedAt.length > 0 && Date.now() - startedAt[0] >= windowMs) startedAt.shift();
			if (startedAt.length >= maxRequests) await sleep(startedAt[0] + windowMs - Date.now());
			startedAt.push(Date.now());
			if (startedAt.length > maxRequests) startedAt.shift();
		});
		queue = turn;
		return turn;
	};
}

export function createNvdClient({
	baseUrl = DEFAULT_BASE_URL,
	apiKey,
	windowMs = WINDOW_MS,
	maxRequests = apiKey ? 50 : 5,
	timeoutMs = 30_000,
	retries = 3,
	backoffMs = 6000,
	pageSize = MAX_PAGE_SIZE
} = {}) {
	const acquire = createLimiter(maxRequests, windowMs);

	async function getJson(path, parameters) {
		const url = `${baseUrl}${path}?${new URLSearchParams(parameters)}`;
		for (let attempt = 0; ; attempt += 1) {
			await acquire();
			let response;
			try {
				response = await fetch(url, { headers: apiKey ? { apiKey } : {}, signal: AbortSignal.timeout(timeoutMs) });
			} catch (error) {
				if (attempt >= retries) throw new NvdError(`NVD request failed: ${error.message}`, { cause: error });
				await sleep(backoffMs * 2 ** attempt);
				continue;
			}
			if (response.ok) return response.json();
			if (!RETRYABLE_STATUSES.has(response.status) || attempt >= retries) throw new NvdError(`NVD answered ${response.status} for ${path}`);
			await sleep(backoffMs * 2 ** attempt);
		}
	}

	// Follow startIndex until totalResults is reached; return the concatenated `itemsKey` arrays.
	async function getAllPages(path, parameters, itemsKey) {
		const items = [];
		let startIndex = 0;
		let totalResults = 0;
		do {
			const page = await getJson(path, { ...parameters, startIndex, resultsPerPage: pageSize });
			const pageItems = page[itemsKey] ?? [];
			items.push(...pageItems);
			totalResults = page.totalResults ?? 0;
			startIndex += pageItems.length;
			if (pageItems.length === 0) break;
		} while (startIndex < totalResults);
		return items;
	}

	return {
		searchCpes: keyword => getAllPages('/cpes/2.0', { keywordSearch: keyword }, 'products'),
		getCvesByCpe: cpeName => getAllPages('/cves/2.0', { cpeName }, 'vulnerabilities')
	};
}

let defaultClient;
// The client configured from NVD_BASE_URL and NVD_API_KEY, created on first use.
export function getNvdClient() {
	defaultClient ??= createNvdClient({ baseUrl: process.env.NVD_BASE_URL || DEFAULT_BASE_URL, apiKey: process.env.NVD_API_KEY || undefined });
	return defaultClient;
}
