import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, cpeMatchCovers, cveAffectsCpe } from '../utils/cpe-match.js';

const CPE = 'cpe:2.3:a:openssl:openssl:3.0.5:-:*:*:*:*:*:*';
const ANY_OPENSSL = 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*';
const range = bounds => ({ vulnerable: true, criteria: ANY_OPENSSL, ...bounds });

describe('compareVersions', () => {
	it('orders numeric tokens numerically, not as text', () => {
		assert.ok(compareVersions('3.0.10', '3.0.9') > 0);
	});

	it('treats openssl letter suffixes as later patches', () => {
		assert.ok(compareVersions('1.1.1m', '1.1.1') > 0);
		assert.ok(compareVersions('1.0.2zb', '1.0.2zd') < 0);
	});

	it('orders pre-releases before their release', () => {
		assert.ok(compareVersions('3.0.0-beta1', '3.0.0') < 0);
		assert.ok(compareVersions('3.0.0', '3.0.0-rc1') > 0);
		assert.ok(compareVersions('3.0.0-alpha2', '3.0.0-beta1') < 0);
		assert.ok(compareVersions('3.0.0-rc1', '3.0.0p1') < 0);
		assert.ok(compareVersions('3.0.0-rc1', '2.9.9') > 0);
	});

	it('keeps single letters as patch releases', () => {
		assert.ok(compareVersions('1.1.1a', '1.1.1') > 0);
	});

	it('finds equal versions equal', () => {
		assert.equal(compareVersions('3.0.0', '3.0.0'), 0);
	});
});

describe('cpeMatchCovers', () => {
	it('matches exact criteria and rejects another version', () => {
		assert.ok(cpeMatchCovers({ vulnerable: true, criteria: 'cpe:2.3:a:openssl:openssl:3.0.5:*:*:*:*:*:*:*' }, CPE));
		assert.ok(!cpeMatchCovers({ vulnerable: true, criteria: 'cpe:2.3:a:openssl:openssl:3.0.6:*:*:*:*:*:*:*' }, CPE));
	});

	it('rejects another product or vendor', () => {
		assert.ok(!cpeMatchCovers({ vulnerable: true, criteria: 'cpe:2.3:a:openssl:libcrypto:3.0.5:*:*:*:*:*:*:*' }, CPE));
		assert.ok(!cpeMatchCovers({ vulnerable: true, criteria: 'cpe:2.3:a:other:openssl:3.0.5:*:*:*:*:*:*:*' }, CPE));
	});

	it('versionStartIncluding is inclusive', () => {
		assert.ok(cpeMatchCovers(range({ versionStartIncluding: '3.0.5' }), CPE));
		assert.ok(!cpeMatchCovers(range({ versionStartIncluding: '3.0.6' }), CPE));
	});

	it('versionStartExcluding is exclusive', () => {
		assert.ok(!cpeMatchCovers(range({ versionStartExcluding: '3.0.5' }), CPE));
		assert.ok(cpeMatchCovers(range({ versionStartExcluding: '3.0.4' }), CPE));
	});

	it('versionEndIncluding is inclusive', () => {
		assert.ok(cpeMatchCovers(range({ versionEndIncluding: '3.0.5' }), CPE));
		assert.ok(!cpeMatchCovers(range({ versionEndIncluding: '3.0.4' }), CPE));
	});

	it('versionEndExcluding is exclusive', () => {
		assert.ok(!cpeMatchCovers(range({ versionEndExcluding: '3.0.5' }), CPE));
		assert.ok(cpeMatchCovers(range({ versionEndExcluding: '3.0.6' }), CPE));
	});

	it('combines start and end bounds', () => {
		assert.ok(cpeMatchCovers(range({ versionStartIncluding: '3.0.0', versionEndExcluding: '3.0.7' }), CPE));
		assert.ok(!cpeMatchCovers(range({ versionStartIncluding: '1.1.1', versionEndExcluding: '1.1.1t' }), CPE));
	});

	it('ignores a non-vulnerable entry', () => {
		assert.ok(!cpeMatchCovers({ ...range({}), vulnerable: false }, CPE));
	});
});

describe('cveAffectsCpe', () => {
	it('needs a vulnerable match in some configuration node', () => {
		const platformOnly = { configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:mutt:mutt:1.5.19:*:*:*:*:*:*:*' }] }, { cpeMatch: [{ vulnerable: false, criteria: ANY_OPENSSL }] }] }] };
		assert.ok(!cveAffectsCpe(platformOnly, CPE));
		assert.ok(cveAffectsCpe({ configurations: [{ nodes: [{ cpeMatch: [range({ versionEndExcluding: '3.0.7' })] }] }] }, CPE));
		assert.ok(!cveAffectsCpe({}, CPE));
	});
});
