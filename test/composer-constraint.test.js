import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { satisfies } from '../utils/composer-constraint.js';

const advisories = JSON.parse(readFileSync(new URL('fixtures/packagist/advisories.json', import.meta.url), 'utf8')).advisories;
const mime45070 = advisories['symfony/mime'].find(({ cve }) => cve === 'CVE-2026-45070').affectedVersions;

describe('satisfies', () => {
	it('reads the real CVE-2026-45070 range: 7.4.19 affected, 7.4.22 not (Packagist says <7.4.22)', () => {
		assert.equal(satisfies('7.4.19', mime45070), true);
		assert.equal(satisfies('v7.4.19', mime45070), true);
		assert.equal(satisfies('7.4.22', mime45070), false);
		assert.equal(satisfies('8.1.10', mime45070), false);
	});

	it('handles OR groups, comma and space ANDs, and every comparison', () => {
		assert.equal(satisfies('2.1.1', '>=2.0.0,<2.0.8|>=2.1.0,<2.1.2'), true);
		assert.equal(satisfies('2.0.9', '>=2.0.0,<2.0.8|>=2.1.0,<2.1.2'), false);
		assert.equal(satisfies('1.5.2', '<=1.5.2'), true);
		assert.equal(satisfies('1.5.2', '>1.5.0 <1.6'), true);
		assert.equal(satisfies('1.5.2', '!=1.5.2'), false);
		assert.equal(satisfies('1.5.2', '=1.5.2'), true);
	});

	it('never answers true for a form it does not read', () => {
		assert.equal(satisfies('7.4.19', '^7.4'), undefined);
		assert.equal(satisfies('7.4.19', '~7.4.0'), undefined);
		assert.equal(satisfies('7.4.19', '7.4.*'), undefined);
		assert.equal(satisfies('dev-develop', '<2.0'), undefined);
	});

	it('still answers true when one readable group matches', () => {
		assert.equal(satisfies('1.0.0', '^2.0|<1.1'), true);
	});
});
