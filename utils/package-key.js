// Ecosystem package => the software key the NVD resolver works on, so direct dependencies go
// through the same CPE pipeline as installed programs. Pure, no I/O.

// target_sw an NVD CPE uses for a package of each ecosystem; `*` (any) is always accepted.
export const ECOSYSTEM_TARGETS = { npm: 'node.js', PyPI: 'python', Packagist: 'php' };

// npm `@scope/name` => vendor scope; Packagist `vendor/name` => vendor; otherwise no vendor.
export function softwareKeyOf({ ecosystem, name, version }) {
	const scoped = ecosystem === 'npm' ? /^@([^/]+)\/(.+)$/.exec(name) : undefined;
	if (scoped) return { vendor: scoped[1], name: scoped[2], version };
	const slash = ecosystem === 'Packagist' ? name.indexOf('/') : -1;
	if (slash > 0) return { vendor: name.slice(0, slash), name: name.slice(slash + 1), version };
	return { vendor: '', name, version };
}
