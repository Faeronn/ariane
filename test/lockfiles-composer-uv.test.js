import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseLockfile } from '../utils/lockfiles/index.js';

const fixture = name => readFileSync(new URL(`fixtures/lockfiles/${name}`, import.meta.url), 'utf8');
const summary = ({ packages }) => packages.map(({ name, version, direct, dev }) => `${name}@${version}${direct ? ' direct' : ''}${dev ? ' dev' : ''}`).toSorted();

describe('parseLockfile composer.lock (real argdoc lockfile, trimmed)', () => {
	it('lists Packagist packages without the v prefix, development ones flagged', () => {
		const result = parseLockfile('composer.lock', fixture('composer.lock'));
		assert.equal(result.ecosystem, 'Packagist');
		assert.deepEqual(summary(result), ['doctrine/dbal@4.5.0', 'doctrine/orm@3.7.5', 'phpunit/phpunit@11.5.57 dev', 'symfony/http-kernel@7.4.21', 'symfony/web-profiler-bundle@7.4.21 dev', 'twig/twig@3.30.0']);
	});

	it('flags the requirements of the composer.json sent along as direct, platform ones ignored', () => {
		const result = parseLockfile('composer.lock', fixture('composer.lock'), { manifests: { 'composer.json': fixture('composer.json') } });
		assert.deepEqual(summary(result), ['doctrine/dbal@4.5.0', 'doctrine/orm@3.7.5 direct', 'phpunit/phpunit@11.5.57 direct dev', 'symfony/http-kernel@7.4.21', 'symfony/web-profiler-bundle@7.4.21 direct dev', 'twig/twig@3.30.0 direct']);
	});

	it('refuses a lockfile without a packages list and a broken composer.json', () => {
		assert.deepEqual(parseLockfile('composer.lock', '{}').errors, ['composer.lock: no "packages" list']);
		assert.match(parseLockfile('composer.lock', fixture('composer.lock'), { manifests: { 'composer.json': '{' } }).errors[0], /^composer\.lock: unreadable/);
	});
});

describe('parseLockfile uv.lock (real mib-cigalieres lockfile)', () => {
	it('lists the PyPI packages of uv tree, the project itself skipped', () => {
		const result = parseLockfile('uv.lock', fixture('uv.lock'));
		assert.equal(result.ecosystem, 'PyPI');
		assert.deepEqual(summary(result), [
			'anyio@4.16.0', 'certifi@2026.10.23', 'colorama@0.4.6 dev', 'h11@0.16.0', 'httpcore@1.0.9', 'httpx@0.28.1 direct', 'idna@3.20',
			'iniconfig@2.3.1 dev', 'packaging@26.3 dev', 'pluggy@1.7.0 dev', 'pygments@2.21.0 dev', 'pytest@9.2.0 direct dev', 'python-dotenv@1.2.4 direct',
			'respx@0.23.1 direct dev', 'ruff@0.17.4 direct dev', 'typing-extensions@4.16.0'
		]);
	});

	it('refuses broken TOML', () => {
		assert.match(parseLockfile('uv.lock', '[[package]\nname = ').errors[0], /^uv\.lock: unreadable/);
	});
});
