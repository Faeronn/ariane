// package-lock.json (lockfileVersion 2 or 3) => the exact packages npm installed. Pure, no I/O.

const NODE_MODULES = 'node_modules/';
const DEPENDENCY_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

// The project (`""`) and its workspaces (keys outside node_modules) declare the direct dependencies.
// npm hoists workspace dependencies to the root node_modules, so the root holds them all.
function declaredDependencies(packages) {
	const declared = new Map([['', new Set()]]);
	for (const [key, entry] of Object.entries(packages)) {
		if (key !== '' && key.includes(NODE_MODULES)) continue;
		const names = DEPENDENCY_FIELDS.flatMap(field => Object.keys(entry?.[field] ?? {}));
		declared.set(key, new Set([...(declared.get(key) ?? []), ...names]));
		for (const name of names) declared.get('').add(name);
	}
	return declared;
}

// `node_modules/a/node_modules/@scope/b` => { parent: 'node_modules/a', name: '@scope/b' }.
function splitKey(key) {
	const index = key.lastIndexOf(NODE_MODULES);
	return { parent: key.slice(0, index).replace(/\/$/, ''), name: key.slice(index + NODE_MODULES.length) };
}

export function parseNpmLockfile(lockfile) {
	if (![2, 3].includes(lockfile?.lockfileVersion) || typeof lockfile.packages !== 'object') {
		return { errors: [`lockfileVersion ${lockfile?.lockfileVersion ?? 'missing'} is not supported (2 or 3, npm 7 and later)`] };
	}

	const declared = declaredDependencies(lockfile.packages);
	const packages = [];
	for (const [key, entry] of Object.entries(lockfile.packages)) {
		// Workspaces and links point at local folders, not at published packages.
		if (!key.includes(NODE_MODULES) || entry?.link || typeof entry?.version !== 'string') continue;
		const { parent, name } = splitKey(key);
		packages.push({ name, version: entry.version, direct: Boolean(declared.get(parent)?.has(name)), dev: Boolean(entry.dev || entry.devOptional) });
	}
	return { ecosystem: 'npm', packages };
}
