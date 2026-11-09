import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateInventory, MAX_SOFTWARE_ENTRIES } from '../utils/inventory.js';

const valid = overrides => ({ hostname: 'web-01', osFamily: 'linux', osVersion: 'Debian 12', collectedAt: '2026-11-09T10:00:00Z', software: [{ name: 'openssl', version: '3.0.0', vendor: 'OpenSSL' }], ...overrides });

describe('validateInventory', () => {
	it('accepts a valid payload and parses collectedAt', () => {
		const { errors, inventory } = validateInventory(valid());
		assert.equal(errors, undefined);
		assert.equal(inventory.osFamily, 'linux');
		assert.equal(inventory.collectedAt.toISOString(), '2026-11-09T10:00:00.000Z');
		assert.deepEqual(inventory.software, [{ vendor: 'openssl', name: 'openssl', version: '3.0.0' }]);
	});

	it('rejects a software entry without name', () => {
		const { errors } = validateInventory(valid({ software: [{ version: '1.0' }] }));
		assert.deepEqual(errors, ['software[0].name is required']);
	});

	it('rejects over-long fields', () => {
		const { errors } = validateInventory(valid({ software: [{ name: 'a'.repeat(256), version: '1'.repeat(101) }] }));
		assert.ok(errors.includes('software[0].name is longer than 255 characters'));
		assert.ok(errors.includes('software[0].version is longer than 100 characters'));
	});

	it(`rejects more than ${MAX_SOFTWARE_ENTRIES} entries`, () => {
		const software = Array.from({ length: MAX_SOFTWARE_ENTRIES + 1 }, (_, index) => ({ name: `pkg${index}`, version: '1' }));
		const { errors } = validateInventory(valid({ software }));
		assert.deepEqual(errors, [`software has more than ${MAX_SOFTWARE_ENTRIES} entries`]);
	});

	it('collapses duplicates after normalization', () => {
		const { inventory } = validateInventory(valid({ software: [{ name: 'Curl', version: '8.0' }, { name: ' curl ', version: '8.0' }, { name: 'curl', version: '8.1' }] }));
		assert.equal(inventory.software.length, 2);
	});

	it('sanitizes and lowercases the matching keys, trims the version', () => {
		const { inventory } = validateInventory(valid({ software: [{ name: ' <Mozilla Firefox> ', vendor: '"Mozilla"', version: ' 120.0 ' }] }));
		assert.deepEqual(inventory.software, [{ vendor: 'mozilla', name: 'mozilla firefox', version: '120.0' }]);
	});

	it('rejects a bad osFamily, a bad date, a non-array software and a non-object body', () => {
		assert.ok(validateInventory(valid({ osFamily: 'macos' })).errors.includes('osFamily must be linux or windows'));
		assert.ok(validateInventory(valid({ collectedAt: 'yesterday' })).errors.includes('collectedAt must be an ISO 8601 date'));
		assert.ok(validateInventory(valid({ software: 'openssl' })).errors.includes('software must be an array'));
		assert.deepEqual(validateInventory([]).errors, ['body must be a JSON object']);
	});

	it('defaults missing vendor and version to empty strings', () => {
		const { inventory } = validateInventory(valid({ software: [{ name: 'tool' }] }));
		assert.deepEqual(inventory.software, [{ vendor: '', name: 'tool', version: '' }]);
	});
});
