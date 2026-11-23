// uv.lock (TOML) => the exact PyPI packages uv resolved. Pure, no I/O.

// The project itself (and its workspace members) are local sources, not published packages.
const isLocal = entry => Boolean(entry.source?.editable || entry.source?.virtual || entry.source?.directory || entry.source?.path);

const names = list => (list ?? []).map(dependency => dependency?.name).filter(Boolean);

// Packages reachable from `start` through the lockfile's dependency lists.
function reachable(start, byName) {
	const seen = new Set();
	const queue = [...start];
	while (queue.length > 0) {
		const name = queue.shift();
		if (seen.has(name)) continue;
		seen.add(name);
		queue.push(...names(byName.get(name)?.dependencies));
	}
	return seen;
}

export function parseUvLockfile(lockfile) {
	if (!Array.isArray(lockfile?.package)) return { errors: ['no [[package]] entries'] };

	const byName = new Map(lockfile.package.map(entry => [entry.name, entry]));
	const roots = lockfile.package.filter(entry => isLocal(entry));
	const direct = new Set(roots.flatMap(root => names(root.dependencies)));
	const groupDirect = new Set(roots.flatMap(root => Object.values(root['dev-dependencies'] ?? {}).flatMap(group => names(group))));
	// Development-only: reachable from the dev groups but not from the runtime dependencies.
	const runtime = reachable(direct, byName);

	const packages = lockfile.package
		.filter(entry => !isLocal(entry) && typeof entry.name === 'string' && typeof entry.version === 'string')
		.map(entry => ({ name: entry.name, version: entry.version, direct: direct.has(entry.name) || groupDirect.has(entry.name), dev: !runtime.has(entry.name) }));
	return { ecosystem: 'PyPI', packages };
}
