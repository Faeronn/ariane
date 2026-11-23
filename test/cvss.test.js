import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { cvssBaseScore, severityOfScore } from '../utils/cvss.js';

// Base scores as given by the FIRST calculator (https://www.first.org/cvss/calculator/3.1).
const VECTORS = [
	['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
	['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1], // GHSA-rv95-896h-c2vc, NVD gives 6.1 for CVE-2024-29041
	['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
	['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
	['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
	['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10],
	['CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8],
	['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0]
];

describe('cvssBaseScore', () => {
	for (const [vector, score] of VECTORS) {
		it(`${vector} => ${score}`, () => assert.equal(cvssBaseScore(vector), score));
	}

	it('gives no score for CVSS v4, v2 or a malformed vector', () => {
		assert.equal(cvssBaseScore('CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L'), undefined);
		assert.equal(cvssBaseScore('AV:N/AC:L/Au:N/C:P/I:P/A:P'), undefined);
		assert.equal(cvssBaseScore('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), undefined);
	});
});

describe('severityOfScore', () => {
	it('follows the FIRST rating table', () => {
		assert.deepEqual([9, 8.9, 7, 6.9, 4, 3.9, 0.1].map(score => severityOfScore(score)), ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW', 'LOW']);
		assert.equal(severityOfScore(0), undefined);
	});
});
