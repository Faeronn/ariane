import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, cpeMatchCovers, cveAffectsCpe, cveConditionsForCpe } from '../utils/cpe-match.js';
import { loadFixture } from './helpers/nvd-stub.js';

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

// Synthetic CVEs in the real NVD configuration shape (see the Mutt case in cves-openssl-3.0.0.json).
const OPENSSL_RANGE = { vulnerable: true, criteria: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', versionEndExcluding: '3.0.2' };
const WINDOWS = 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*';
const plain = { configurations: [{ nodes: [{ operator: 'OR', cpeMatch: [OPENSSL_RANGE] }] }] };
const onWindows = { configurations: [{ operator: 'AND', nodes: [{ operator: 'OR', cpeMatch: [OPENSSL_RANGE] }, { operator: 'OR', cpeMatch: [{ vulnerable: false, criteria: WINDOWS }] }] }] };

const real = id => loadFixture('cves-openssl-3.0.0.json').vulnerabilities.find(({ cve }) => cve.id === id).cve;

describe('cveConditionsForCpe', () => {
	const OPENSSL = 'cpe:2.3:a:openssl:openssl:3.0.0:-:*:*:*:*:*:*';

	it('gives no condition for a plain configuration (real CVE-2022-3996)', () => {
		assert.deepEqual(cveConditionsForCpe(real('CVE-2022-3996'), OPENSSL), { platforms: [] });
		assert.deepEqual(cveConditionsForCpe(plain, OPENSSL), { platforms: [] });
	});

	it('returns the platform criteria of an AND configuration', () => {
		assert.deepEqual(cveConditionsForCpe(onWindows, OPENSSL), { platforms: [WINDOWS] });
	});

	it('lets one unconditional configuration override conditional ones', () => {
		const mixed = { configurations: [...onWindows.configurations, ...plain.configurations] };
		assert.deepEqual(cveConditionsForCpe(mixed, OPENSSL), { platforms: [] });
	});

	it('still ignores a CPE that is only a non-vulnerable platform (real Mutt CVE-2009-1390)', () => {
		assert.equal(cveConditionsForCpe(real('CVE-2009-1390'), OPENSSL), undefined);
	});
});

const teamsRange = (targetSw, versionEndExcluding) => ({ vulnerable: true, criteria: `cpe:2.3:a:microsoft:teams:*:*:*:*:*:${targetSw}:*:*`, versionEndExcluding });
const single = matches => ({ configurations: [{ nodes: [{ operator: 'OR', cpeMatch: matches }] }] });

describe('cveConditionsForCpe with a target_sw OS', () => {
	const teams = loadFixture('cve-2023-29328.json').vulnerabilities[0].cve;
	const IPHONE = 'cpe:2.3:o:apple:iphone_os:-:*:*:*:*:*:*:*';

	it('limits a CPE covered only by an iphone_os range to iOS (real CVE-2023-29328)', () => {
		// 1.26 is above the Windows (< 1.6.00.18681) and Android ranges, below the iOS one (< 5.12.1).
		assert.deepEqual(cveConditionsForCpe(teams, 'cpe:2.3:a:microsoft:teams:1.26.27102:*:*:*:*:*:*:*'), { platforms: [IPHONE] });
	});

	it('keeps an unrestricted target_sw (- or *) unconditional', () => {
		assert.deepEqual(cveConditionsForCpe(teams, 'cpe:2.3:a:microsoft:teams:1.5.0:*:*:*:*:*:*:*'), { platforms: [] });
		assert.deepEqual(cveConditionsForCpe(single([teamsRange('*', '2.0')]), 'cpe:2.3:a:microsoft:teams:1.0:*:*:*:*:*:*:*'), { platforms: [] });
	});

	it('lists every targeted OS when several covering ranges name one', () => {
		const conditions = cveConditionsForCpe(single([teamsRange('windows', '2.0'), teamsRange('iphone_os', '2.0')]), 'cpe:2.3:a:microsoft:teams:1.0:*:*:*:*:*:*:*');
		assert.deepEqual(conditions.platforms.toSorted(), [IPHONE, 'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*'].toSorted());
	});

	it('treats a target_sw that is not an OS as unrestricted', () => {
		assert.deepEqual(cveConditionsForCpe(single([teamsRange('node.js', '2.0')]), 'cpe:2.3:a:microsoft:teams:1.0:*:*:*:*:*:*:*'), { platforms: [] });
	});
});
