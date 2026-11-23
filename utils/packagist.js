// Packagist security advisories API (https://packagist.org/apidoc#list-security-advisories): the
// advisories `composer audit` reads, aggregated from GitHub and FriendsOfPHP, per package name with
// the affected version ranges. No key.
const DEFAULT_BASE_URL = 'https://packagist.org';
const MAX_PACKAGES = 100;
const RETRYABLE = status => status === 429 || status >= 500;

export class PackagistError extends Error {
	constructor(message, options) {
		super(message, options);
		this.name = 'PackagistError';
	}
}

const sleep = milliseconds => new Promise(resolve => { setTimeout(resolve, milliseconds); });

export function createPackagistClient({ baseUrl = DEFAULT_BASE_URL, timeoutMs = 30_000, retries = 3, backoffMs = 2000 } = {}) {
	function send(names) {
		return fetch(`${baseUrl}/api/security-advisories/`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: names.map(name => `packages[]=${encodeURIComponent(name)}`).join('&'),
			signal: AbortSignal.timeout(timeoutMs)
		}).then(response => ({ response }), error => ({ error }));
	}

	async function request(names) {
		for (let attempt = 0; ; attempt += 1) {
			const { response, error } = await send(names);
			if (response?.ok) return response.json();
			const retryable = error || RETRYABLE(response.status);
			if (!retryable || attempt >= retries) {
				throw new PackagistError(error ? `Packagist request failed: ${error.message}` : `Packagist answered ${response.status}`, error ? { cause: error } : undefined);
			}
			await sleep(backoffMs * 2 ** attempt);
		}
	}

	return {
		// Advisories of every package name, as { name: [advisory, ...] }; names without any are absent.
		async advisories(names) {
			const unique = [...new Set(names)];
			const result = {};
			for (let start = 0; start < unique.length; start += MAX_PACKAGES) {
				const page = await request(unique.slice(start, start + MAX_PACKAGES));
				Object.assign(result, page.advisories ?? {});
			}
			return result;
		}
	};
}

let defaultClient;
// The client configured from PACKAGIST_BASE_URL, created on first use.
export function getPackagistClient() {
	defaultClient ??= createPackagistClient({ baseUrl: process.env.PACKAGIST_BASE_URL || DEFAULT_BASE_URL });
	return defaultClient;
}
