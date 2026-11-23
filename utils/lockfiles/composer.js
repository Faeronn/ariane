// composer.lock => the exact Packagist packages Composer installed. Pure, no I/O.

// Platform requirements (php, extensions, libraries) are not Packagist packages.
const isPlatform = name => name === 'php' || /^(?:ext|lib|composer)-/.test(name);

// Packagist and OSV write versions without the `v` tags often carry (v6.4.0 => 6.4.0).
const releaseVersion = version => version.replace(/^v(?=\d)/, '');

// Direct dependencies come from the project's composer.json, when the agent sent it along.
function declaredDependencies(manifest) {
	if (!manifest) return;
	return new Set(['require', 'require-dev'].flatMap(field => Object.keys(manifest[field] ?? {})).filter(name => !isPlatform(name)));
}

export function parseComposerLockfile(lockfile, { manifest } = {}) {
	if (!Array.isArray(lockfile?.packages)) return { errors: ['no "packages" list'] };

	const declared = declaredDependencies(manifest);
	const packages = [
		...lockfile.packages.map(entry => ({ entry, dev: false })),
		...(lockfile['packages-dev'] ?? []).map(entry => ({ entry, dev: true }))
	]
		.filter(({ entry }) => typeof entry?.name === 'string' && typeof entry.version === 'string')
		.map(({ entry, dev }) => ({ name: entry.name, version: releaseVersion(entry.version), direct: Boolean(declared?.has(entry.name)), dev }));
	return { ecosystem: 'Packagist', packages };
}
