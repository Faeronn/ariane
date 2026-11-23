import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { softwareKeyOf } from '../utils/package-key.js';

describe('softwareKeyOf', () => {
	it('maps each ecosystem package to a software key', () => {
		assert.deepEqual(softwareKeyOf({ ecosystem: 'npm', name: 'express', version: '4.17.1' }), { vendor: '', name: 'express', version: '4.17.1' });
		assert.deepEqual(softwareKeyOf({ ecosystem: 'npm', name: '@angular/core', version: '21.0.0' }), { vendor: 'angular', name: 'core', version: '21.0.0' });
		assert.deepEqual(softwareKeyOf({ ecosystem: 'Packagist', name: 'symfony/http-kernel', version: '7.4.21' }), { vendor: 'symfony', name: 'http-kernel', version: '7.4.21' });
		assert.deepEqual(softwareKeyOf({ ecosystem: 'PyPI', name: 'requests', version: '2.25.0' }), { vendor: '', name: 'requests', version: '2.25.0' });
	});
});
