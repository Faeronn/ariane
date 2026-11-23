import { parseNpmLockfile } from './npm.js';

// Lockfile name => how to read its content and turn it into packages.
const PARSERS = new Map([
	['package-lock.json', { read: JSON.parse, parse: parseNpmLockfile }]
]);

export const SUPPORTED_LOCKFILES = [...PARSERS.keys()];

// Packages of one lockfile: { ecosystem, packages: [{ name, version, direct, dev }] }, one entry per
// (name, version) with the flags of all its occurrences merged; or { errors } naming the file.
export function parseLockfile(filename, content) {
	const parser = PARSERS.get(filename);
	if (!parser) return { errors: [`${filename}: not a supported lockfile (${SUPPORTED_LOCKFILES.join(', ')})`] };

	let document;
	try {
		document = parser.read(content);
	} catch (error) {
		return { errors: [`${filename}: unreadable (${error.message})`] };
	}
	const { ecosystem, packages, errors } = parser.parse(document);
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
