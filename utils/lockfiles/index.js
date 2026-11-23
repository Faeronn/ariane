import { parse as parseToml } from 'smol-toml';
import { parseNpmLockfile } from './npm.js';
import { parseComposerLockfile } from './composer.js';
import { parseUvLockfile } from './uv.js';

// Lockfile name => how to read its content, turn it into packages, and the manifest that may come
// with it to tell direct dependencies apart (composer.lock lists no project requirements).
const PARSERS = new Map([
	['package-lock.json', { read: JSON.parse, parse: parseNpmLockfile }],
	['composer.lock', { read: JSON.parse, parse: parseComposerLockfile, manifest: 'composer.json' }],
	['uv.lock', { read: parseToml, parse: parseUvLockfile }]
]);

export const SUPPORTED_LOCKFILES = [...PARSERS.keys()];
// Files accepted next to a lockfile, read only to complete it.
export const SUPPORTED_MANIFESTS = [...PARSERS.values()].map(({ manifest }) => manifest).filter(Boolean);

// Packages of one lockfile: { ecosystem, packages: [{ name, version, direct, dev }] }, one entry per
// (name, version) with the flags of all its occurrences merged; or { errors } naming the file.
// `manifests`: contents of companion manifests by file name (composer.json).
export function parseLockfile(filename, content, { manifests = {} } = {}) {
	const parser = PARSERS.get(filename);
	if (!parser) return { errors: [`${filename}: not a supported lockfile (${SUPPORTED_LOCKFILES.join(', ')})`] };

	let document;
	let manifest;
	try {
		document = parser.read(content);
		if (parser.manifest && manifests[parser.manifest] !== undefined) manifest = JSON.parse(manifests[parser.manifest]);
	} catch (error) {
		return { errors: [`${filename}: unreadable (${error.message.split('\n')[0]})`] };
	}
	const { ecosystem, packages, errors } = parser.parse(document, { manifest });
	if (errors) return { errors: errors.map(error => `${filename}: ${error}`) };
	return { ecosystem, packages: mergeDuplicates(packages) };
}

// The same package version installed twice (nested copies) is one package: direct when any copy
// is, development-only when every copy is.
function mergeDuplicates(packages) {
	const merged = new Map();
	for (const item of packages) {
		const key = `${item.name}@${item.version}`;
		const known = merged.get(key);
		merged.set(key, known ? { ...known, direct: known.direct || item.direct, dev: known.dev && item.dev } : item);
	}
	return [...merged.values()];
}
