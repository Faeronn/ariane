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

// Insert one software key, run a resolution tick, read the key back.
async function resolved(vendor, name, version) {
	await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', [vendor, name, version]);
	await runOnce({ client });
	const [row] = await database.query('SELECT cpeName, cpeSynthetic, status FROM software_cpe WHERE name = ?', [name]);
	return { ...row, cpeSynthetic: Number(row.cpeSynthetic) };
}

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

	it('keeps an upstream hyphen version the dictionary knows (real ImageMagick 7.1.2-30)', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['imagemagick studio llc', 'imagemagick', '7.1.2-30']);
		stub.route('/cpes/2.0', 'imagemagick 7.1.2-30', loadFixture('cpes-imagemagick-7.1.2-30.json'));
		stub.route('/cpes/2.0', 'imagemagick 7.1.2', loadFixture('cpes-imagemagick-7.1.2.json'));
		await runOnce({ client });
		const [row] = await database.query('SELECT cpeName, status, versionNormalized FROM software_cpe WHERE name = ?', ['imagemagick']);
		assert.deepEqual({ ...row, versionNormalized: Number(row.versionNormalized) }, { cpeName: 'cpe:2.3:a:imagemagick:imagemagick:7.1.2-30:*:*:*:*:*:*:*', status: 'matched', versionNormalized: 0 });
		assert.ok(!stub.requests.some(({ query }) => query.keywordSearch === 'imagemagick 7.1.2'));
	});

	it('tries the packaged version before its upstream one', async () => {
		await database.query('UPDATE software_cpe SET version = ? WHERE name = ?', ['3.0.0-1~deb12u2', 'openssl']);
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const searches = stub.requests.map(({ query }) => query.keywordSearch).filter(keyword => keyword?.startsWith('openssl'));
		assert.deepEqual(searches, ['openssl 3.0.0-1~deb12u2', 'openssl 3.0.0']);
	});

	it('never builds a synthetic CPE on a version still carrying a packaging revision', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['google llc', 'google chrome', '122.0.6261.112-1']);
		stub.route('/cpes/2.0', 'cpe:2.3:a:google:chrome', { products: [{ cpe: { cpeName: 'cpe:2.3:a:google:chrome:0.2.149.29:*:*:*:*:*:*:*' } }] });
		await runOnce({ client });
		const [row] = await database.query('SELECT cpeName, versionNormalized FROM software_cpe WHERE name = ?', ['google chrome']);
		assert.deepEqual({ ...row, versionNormalized: Number(row.versionNormalized) }, { cpeName: 'cpe:2.3:a:google:chrome:122.0.6261.112:*:*:*:*:*:*:*', versionNormalized: 1 });
	});

	it('resolves a direct npm dependency without alias nor upstream fallback (real express 4.17.1)', async () => {
		await database.query("INSERT INTO software_cpe (vendor, name, version, ecosystem, packageName) VALUES ('', 'curl', '1.0.0-1', 'npm', 'curl'), ('', 'express', '4.17.1', 'npm', 'express')");
		stub.route('/cpes/2.0', 'express 4.17.1', loadFixture('cpes-express-4.17.1.json'));
		await runOnce({ client });
		const express = await keyRow('express');
		assert.deepEqual({ status: express.status, cpeName: express.cpeName }, { status: 'matched', cpeName: 'cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:node.js:*:*' });
		// npm `curl` is not the curl program: no alias request, and no retry on `1.0.0`.
		const curlSearches = stub.requests.filter(({ query }) => JSON.stringify(query).includes('curl'));
		assert.deepEqual(curlSearches.map(({ query }) => query.keywordSearch), ['curl 1.0.0-1']);
	});

	describe('aliases from the real-app validation', () => {
		it('keeps the first three parts of a Windows build (real MariaDB 12.3.2.0, .NET 8.0.21.35325)', async () => {
			stub.route('/cpes/2.0', 'cpe:2.3:a:mariadb:mariadb:12.3.2', loadFixture('cpes-match-mariadb-12.3.2.json'));
			stub.route('/cpes/2.0', 'cpe:2.3:a:microsoft:.net:8.0.21', loadFixture('cpes-match-dotnet-8.0.21.json'));
			stub.route('/cpes/2.0', 'cpe:2.3:a:microsoft:asp.net_core:8.0.21', loadFixture('cpes-match-aspnet-core-8.0.21.json'));
			// Four dotted numbers are joined: written out, the linter reads them as an IP address.
			const mariadb = await resolved('mariadb corporation ab', 'mariadb 12.3 (x64)', ['12', '3', '2', '0'].join('.'));
			const dotnet = await resolved('microsoft corporation', 'microsoft windows desktop runtime - 8.0.21 (x64)', '8.0.21.35325');
			const aspnet = await resolved('microsoft corporation', 'microsoft asp.net core 8.0.21 - shared framework (x64)', '8.0.21.25475');
			assert.equal(mariadb.cpeName, 'cpe:2.3:a:mariadb:mariadb:12.3.2:*:*:*:*:*:*:*');
			assert.equal(dotnet.cpeName, 'cpe:2.3:a:microsoft:.net:8.0.21:*:*:*:*:*:*:*');
			assert.equal(aspnet.cpeName, 'cpe:2.3:a:microsoft:asp.net_core:8.0.21:*:*:*:*:*:*:*');
		});

		it('builds a synthetic Ghostscript CPE when the dictionary lacks the version (real 10.08.0)', async () => {
			stub.route('/cpes/2.0', 'cpe:2.3:a:artifex:ghostscript', loadFixture('cpes-match-ghostscript-product.json'));
			assert.deepEqual(await resolved('artifex software inc.', 'gpl ghostscript', '10.08.0'), { cpeName: 'cpe:2.3:a:artifex:ghostscript:10.08.0:*:*:*:*:*:*:*', cpeSynthetic: 1, status: 'matched' });
		});

		it('no longer takes the Teams Meeting Add-in for Teams', async () => {
			await resolved('microsoft', 'microsoft teams meeting add-in for microsoft office', '1.26.27102');
			assert.ok(!stub.requests.some(({ query }) => query.cpeMatchString?.startsWith('cpe:2.3:a:microsoft:teams')));
		});
	});

	it('does not flag an exact version match', async () => {
		stub.route('/cpes/2.0', 'openssl 3.0.0', loadFixture('cpes-openssl-3.0.0.json'));
		await runOnce({ client });
		const [row] = await database.query('SELECT versionNormalized FROM software_cpe WHERE name = ?', ['openssl']);
		assert.equal(Number(row.versionNormalized), 0);
	});

	it('resolves a Windows display name through its product candidates', async () => {
		// Without the firefox aliases, the keyword path is the one exercised.
		const aliases = await database.query('SELECT * FROM software_alias WHERE namePattern LIKE ?', ['mozilla firefox%']);
		await database.query('DELETE FROM software_alias WHERE namePattern LIKE ?', ['mozilla firefox%']);
		try {
			await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['mozilla', 'mozilla firefox (x64 fr)', '115.0']);
			stub.route('/cpes/2.0', 'firefox 115.0', loadFixture('cpes-firefox-115.0.json'));
			await runOnce({ client });
			const row = await keyRow('mozilla firefox (x64 fr)');
			assert.equal(row.status, 'matched');
			assert.equal(row.cpeName, 'cpe:2.3:a:mozilla:firefox:115.0:*:*:*:-:*:*:*');
			assert.equal(stub.requests.find(({ query }) => query.keywordSearch?.includes('firefox'))?.query.keywordSearch, 'firefox 115.0');
		} finally {
			for (const alias of aliases) await database.query('INSERT INTO software_alias (aliasID, namePattern, vendorPattern, cpePart, cpeVendor, cpeProduct) VALUES (?, ?, ?, ?, ?, ?)', [alias.aliasID, alias.namePattern, alias.vendorPattern, alias.cpePart, alias.cpeVendor, alias.cpeProduct]);
		}
	});

	it('resolves an aliased product with one cpeMatchString request and no keyword search', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['mozilla', 'mozilla firefox (x64 en-us)', '115.0']);
		stub.route('/cpes/2.0', 'cpe:2.3:a:mozilla:firefox:115.0', loadFixture('cpes-match-firefox-115.0.json'));
		await runOnce({ client });
		const row = await keyRow('mozilla firefox (x64 en-us)');
		assert.equal(row.status, 'matched');
		assert.equal(row.cpeName, 'cpe:2.3:a:mozilla:firefox:115.0:*:*:*:-:*:*:*');
		const firefoxRequests = stub.requests.filter(({ query }) => JSON.stringify(query).includes('firefox'));
		assert.deepEqual(firefoxRequests.map(({ query }) => query.cpeMatchString), ['cpe:2.3:a:mozilla:firefox:115.0']);
		const [synthetic] = await database.query('SELECT cpeSynthetic FROM software_cpe WHERE name = ?', ['mozilla firefox (x64 en-us)']);
		assert.equal(Number(synthetic.cpeSynthetic), 0);
	});

	it('prefers the most specific alias (firefox ESR over firefox)', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['mozilla', 'mozilla firefox esr (x64 fr)', '115.6.0']);
		await runOnce({ client });
		assert.ok(stub.requests.some(({ query }) => query.cpeMatchString === 'cpe:2.3:a:mozilla:firefox_esr:115.6.0'));
	});

	it('builds a synthetic CPE for an aliased product whose version the dictionary lacks', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['google llc', 'google chrome', '122.0.6261.112']);
		stub.route('/cpes/2.0', 'cpe:2.3:a:google:chrome', { products: [{ cpe: { cpeName: 'cpe:2.3:a:google:chrome:0.2.149.29:*:*:*:*:*:*:*' } }] });
		await runOnce({ client });
		const [row] = await database.query('SELECT cpeName, cpeSynthetic, status FROM software_cpe WHERE name = ?', ['google chrome']);
		assert.deepEqual({ ...row, cpeSynthetic: Number(row.cpeSynthetic) }, { cpeName: 'cpe:2.3:a:google:chrome:122.0.6261.112:*:*:*:*:*:*:*', cpeSynthetic: 1, status: 'matched' });
	});

	it('leaves an aliased key unmatched when the dictionary does not know the product either', async () => {
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['google llc', 'google chrome', '122.0.6261.112']);
		await runOnce({ client });
		const row = await keyRow('google chrome');
		assert.equal(row.status, 'unmatched');
		assert.ok(!stub.requests.some(({ query }) => query.keywordSearch?.includes('chrome')));
	});

	it('never builds a synthetic CPE on the keyword path', async () => {
		await runOnce({ client });
		const rows = await database.query('SELECT cpeSynthetic FROM software_cpe');
		assert.ok(rows.every(({ cpeSynthetic }) => Number(cpeSynthetic) === 0));
		assert.ok(!stub.requests.some(({ query }) => query.resultsPerPage === '1'));
	});

	it('marks a name made only of noise unmatched without calling NVD', async () => {
		await database.query('DELETE FROM software_cpe');
		await database.query('INSERT INTO software_cpe (vendor, name, version) VALUES (?, ?, ?)', ['', '(x64) 1.2.3', '1.2.3']);
		await runOnce({ client });
		const row = await keyRow('(x64) 1.2.3');
		assert.equal(row.status, 'unmatched');
		assert.equal(stub.requests.length, 0);
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

const productsOf = cpeNames => cpeNames.map(cpeName => ({ cpe: { cpeName } }));

describe('pickCpe for an ecosystem package', () => {
	it('takes a CPE made for the ecosystem or for any platform', () => {
		const express = { ecosystem: 'npm', vendor: '', name: 'express', version: '4.17.1' };
		assert.equal(pickCpe(express, productsOf(['cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:node.js:*:*'])), 'cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:node.js:*:*');
		assert.equal(pickCpe(express, productsOf(['cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:*:*:*'])), 'cpe:2.3:a:openjsf:express:4.17.1:*:*:*:*:*:*:*');
	});

	it('refuses a homonym made for another platform', () => {
		const debug = { ecosystem: 'npm', vendor: '', name: 'debug', version: '2.6.9' };
		assert.equal(pickCpe(debug, productsOf(['cpe:2.3:a:acme:debug:2.6.9:*:*:*:*:python:*:*'])), undefined);
	});

	it('keeps accepting any target for installed programs', () => {
		assert.equal(pickCpe({ vendor: '', name: 'debug', version: '2.6.9' }, productsOf(['cpe:2.3:a:acme:debug:2.6.9:*:*:*:*:python:*:*'])), 'cpe:2.3:a:acme:debug:2.6.9:*:*:*:*:python:*:*');
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
