import { describe, it, before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { api, createSignedInUser, captureLogs } from './helpers/fixtures.js';
import { startNvdStub, loadFixture } from './helpers/nvd-stub.js';
import { runOnce, pickCpe, upstreamVersion } from '../jobs/resolve-cpe.js';
import { createNvdClient } from '../utils/nvd.js';
import { startServer } from './helpers/server.js';
import { reset } from './helpers/database.js';
import database from '../utils/database.js';

const OPENSSL_CPE = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';

let server;
let stub;
let client;
before(async () => {
	server = await startServer();
	stub = await startNvdStub();
	client = createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1, timeoutMs: 500 });
});
after(async () => {
	await stub.close();
	await server.close();
});

beforeEach(async () => {
	await reset();
	stub.reset();
	const { accessToken: token } = await createSignedInUser(server.baseUrl);
	const { body: machine } = await api(server.baseUrl, 'POST', '/machines', { token, body: { hostname: 'web-01' } });
	await api(server.baseUrl, 'POST', '/agents/inventory', {
		headers: { 'X-Agent-Key': machine.apiKey },
		body: { osFamily: 'linux', software: [{ name: 'openssl', vendor: 'openssl', version: '3.0.0' }, { name: 'zzqx unknowntool', version: '1.0' }] }
	});
});

const keyRow = async name => {
	const [row] = await database.query('SELECT cpeName, status, lastCheckedAt FROM software_cpe WHERE name = ?', [name]);
	return row;
};

describe('ingestion', () => {
	it('registers each new software key as pending', async () => {
		const rows = await database.query('SELECT name, status FROM software_cpe ORDER BY name');
		assert.deepEqual(rows.map(({ name, status }) => `${name}:${status}`), ['openssl:pending', 'zzqx unknowntool:pending']);
	});
});

describe('resolve-cpe runOnce', () => {
	it('matches openssl 3.0.0 to its release CPE', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const row = await keyRow('openssl');
		assert.equal(row.status, 'matched');
		assert.equal(row.cpeName, OPENSSL_CPE);
	});

	it('stores the deprecatedBy replacement of a deprecated name', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0-deprecated-only.json'));
		await runOnce({ client });
		const row = await keyRow('openssl');
		assert.equal(row.status, 'matched');
		assert.equal(row.cpeName, OPENSSL_CPE);
	});

	it('matches a distribution package on its upstream version and flags it', async () => {
		await database.query('UPDATE software_cpe SET version = ? WHERE name = ?', ['3.0.0-1~deb12u2', 'openssl']);
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const [row] = await database.query('SELECT cpeName, status, versionNormalized FROM software_cpe WHERE name = ?', ['openssl']);
		assert.equal(row.status, 'matched');
		assert.equal(row.cpeName, OPENSSL_CPE);
		assert.equal(Number(row.versionNormalized), 1);
	});

	it('does not flag an exact version match', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const [row] = await database.query('SELECT versionNormalized FROM software_cpe WHERE name = ?', ['openssl']);
		assert.equal(Number(row.versionNormalized), 0);
	});

	it('marks an unknown tool unmatched with lastCheckedAt set', async () => {
		stub.route('/cpes/2.0', 'zzqx unknowntool 1.0', loadFixture('cpes-empty.json'));
		await runOnce({ client });
		const row = await keyRow('zzqx unknowntool');
		assert.equal(row.status, 'unmatched');
		assert.ok(!row.cpeName);
		assert.ok(row.lastCheckedAt);
	});

	it('retries after a 503 with backoff and does not crash', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		stub.failNext(503, 2);
		const summary = await runOnce({ client });
		assert.equal(summary.failed, 0);
		const openssl = await keyRow('openssl');
		assert.equal(openssl.status, 'matched');
	});

	it('survives an NVD outage: tick ends early, keys stay pending', async () => {
		stub.failNext(403, 50);
		const logs = captureLogs();
		let summary;
		try {
			summary = await runOnce({ client: createNvdClient({ baseUrl: stub.baseUrl, windowMs: 50, maxRequests: 100, backoffMs: 1, retries: 1 }) });
		} finally {
			logs.restore();
		}
		assert.equal(summary.failed, 1);
		const openssl = await keyRow('openssl');
		assert.equal(openssl.status, 'pending');
	});

	it('leaves recently checked unmatched keys alone and retries stale ones', async () => {
		await database.query('UPDATE software_cpe SET status = \'unmatched\', lastCheckedAt = UTC_TIMESTAMP()');
		await runOnce({ client });
		assert.equal(stub.requests.length, 0);

		await database.query('UPDATE software_cpe SET lastCheckedAt = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 8 DAY) WHERE name = \'openssl\'');
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const openssl = await keyRow('openssl');
		assert.equal(openssl.status, 'matched');
	});
});

describe('pickCpe', () => {
	const products = loadFixture('cpes-openssl-3.0.0.json').products;

	it('ignores pre-releases and other versions', () => {
		assert.equal(pickCpe({ vendor: '', name: 'openssl', version: '3.0.1' }, products), undefined);
	});

	it('needs the product name to match', () => {
		assert.equal(pickCpe({ vendor: '', name: 'libressl', version: '3.0.0' }, products), undefined);
	});

	it('matches without a vendor and maps spaces to underscores', () => {
		const product = { cpe: { deprecated: false, cpeName: 'cpe:2.3:a:mozilla:firefox_esr:115.0:*:*:*:*:*:*:*' } };
		assert.equal(pickCpe({ vendor: '', name: 'Firefox ESR', version: '115.0' }, [product]), product.cpe.cpeName);
	});

	it('refuses an ambiguous match between vendors', () => {
		const ambiguous = [
			{ cpe: { deprecated: false, cpeName: 'cpe:2.3:a:acme:tool:1.0:*:*:*:*:*:*:*' } },
			{ cpe: { deprecated: false, cpeName: 'cpe:2.3:a:other:tool:1.0:*:*:*:*:*:*:*' } }
		];
		assert.equal(pickCpe({ vendor: '', name: 'tool', version: '1.0' }, ambiguous), undefined);
		assert.equal(pickCpe({ vendor: 'acme', name: 'tool', version: '1.0' }, ambiguous), 'cpe:2.3:a:acme:tool:1.0:*:*:*:*:*:*:*');
	});
});

describe('upstreamVersion', () => {
	it('drops distribution revisions, epochs and repack suffixes', () => {
		assert.equal(upstreamVersion('3.0.11-1~deb12u2'), '3.0.11');
		assert.equal(upstreamVersion('3.0.2-0ubuntu1.15'), '3.0.2');
		assert.equal(upstreamVersion('3.0.7-27.el9'), '3.0.7');
		assert.equal(upstreamVersion('1:9.18.24-1'), '9.18.24');
		assert.equal(upstreamVersion('2.4.1+dfsg-3'), '2.4.1');
	});

	it('keeps plain and pre-release versions', () => {
		assert.equal(upstreamVersion('3.0.0'), '3.0.0');
		assert.equal(upstreamVersion('3.0.0-beta1'), '3.0.0-beta1');
		assert.equal(upstreamVersion('122.0.6261.112'), '122.0.6261.112');
	});
});
