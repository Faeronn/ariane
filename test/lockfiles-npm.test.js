import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseLockfile } from '../utils/lockfiles/index.js';

const fixture = name => readFileSync(new URL(`fixtures/lockfiles/${name}`, import.meta.url), 'utf8');
const summary = ({ packages }) => packages.map(({ name, version, direct, dev }) => `${name}@${version}${direct ? ' direct' : ''}${dev ? ' dev' : ''}`).toSorted();

describe('parseLockfile package-lock.json', () => {
	it('lists the installed packages of a workspace project (real gesdoc2 lockfile, trimmed)', () => {
		const result = parseLockfile('package-lock.json', fixture('npm-workspaces-package-lock.json'));
		assert.equal(result.ecosystem, 'npm');
		assert.deepEqual(summary(result), [
			'ajv@6.15.0 dev',
			'ajv@8.20.0 dev', // nested copy under @angular-devkit/core keeps its own version
			'express@5.3.0 direct', // declared by the apps/api workspace
			'fsevents@2.3.3 dev',
			'nodemailer@10.2.0 direct',
			'typescript@6.0.3 direct dev' // declared by the root devDependencies
		]);
	});

	it('skips the project, its workspaces and their links', () => {
		const { packages } = parseLockfile('package-lock.json', fixture('npm-workspaces-package-lock.json'));
		assert.ok(!packages.some(({ name }) => name.startsWith('@gesdoc2/')));
	});

	it('merges two copies of the same version, direct when one copy is', () => {
		const lockfile = { lockfileVersion: 3, packages: {
			'': { dependencies: { ms: '2.1.3' } },
			'node_modules/ms': { version: '2.1.3' },
			'node_modules/debug/node_modules/ms': { version: '2.1.3', dev: true }
		} };
		assert.deepEqual(summary(parseLockfile('package-lock.json', JSON.stringify(lockfile))), ['ms@2.1.3 direct']);
	});

	it('refuses a lockfile version 1, naming the file and the reason', () => {
		const result = parseLockfile('package-lock.json', JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
		assert.deepEqual(result.errors, ['package-lock.json: lockfileVersion 1 is not supported (2 or 3, npm 7 and later)']);
	});

	it('refuses broken JSON and an unknown file name', () => {
		assert.match(parseLockfile('package-lock.json', '{ "lockfileVersion": 3,').errors[0], /^package-lock\.json: unreadable/);
		assert.match(parseLockfile('yarn.lock', '').errors[0], /^yarn\.lock: not a supported lockfile/);
	});
});
