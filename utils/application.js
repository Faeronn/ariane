import path from 'node:path';
import sanitizeInput from './sanitizer.js';
import { parseLockfile, SUPPORTED_LOCKFILES, SUPPORTED_MANIFESTS } from './lockfiles/index.js';

export const MAX_PACKAGES = 20_000;
const MAX_FILES = 20;
const MAX_ERRORS = 20;
const LIMITS = { name: 255, path: 1024, packageName: 255, packageVersion: 100 };

// Validate an agent's application payload and parse its lockfiles:
// { name, path?, lockfiles: [{ filename, content }] } where filename is a lockfile name, or a
// manifest completing one (composer.json). Returns { errors } or
// { application: { name, path, packages: [{ ecosystem, name, version, direct, dev }] } }.
export function validateApplication(payload) {
	if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { errors: ['body must be a JSON object'] };
	const errors = [];

	const name = readText(payload.name, 'name', errors);
	if (!name) errors.push('name is required');
	const appPath = readText(payload.path, 'path', errors);
	const files = readFiles(payload.lockfiles, errors);
	if (errors.length > 0) return { errors: errors.slice(0, MAX_ERRORS) };

	const packages = parseFiles(files, errors);
	if (packages.length > MAX_PACKAGES) errors.push(`lockfiles hold more than ${MAX_PACKAGES} packages`);
	for (const item of packages) {
		if (item.name.length > LIMITS.packageName || item.version.length > LIMITS.packageVersion) errors.push(`${item.ecosystem} package ${item.name.slice(0, 50)} has a name or version too long`);
	}
	if (errors.length > 0) return { errors: errors.slice(0, MAX_ERRORS) };
	return { application: { name, path: appPath, packages } };
}

function readText(value, field, errors) {
	if (value === undefined || value === null) return;
	if (typeof value !== 'string') {
		errors.push(`${field} must be a string`);
		return;
	}
	const cleaned = sanitizeInput(value).trim();
	if (cleaned.length > LIMITS[field]) errors.push(`${field} is longer than ${LIMITS[field]} characters`);
	return cleaned || undefined;
}

// Files keyed by their base name: an agent may send paths, only the name tells the format.
function readFiles(entries, errors) {
	if (!Array.isArray(entries) || entries.length === 0) {
		errors.push('lockfiles must be a non-empty array');
		return new Map();
	}
	if (entries.length > MAX_FILES) errors.push(`lockfiles has more than ${MAX_FILES} files`);

	const files = new Map();
	for (const [index, entry] of entries.entries()) {
		const filename = typeof entry?.filename === 'string' ? path.basename(entry.filename.replaceAll('\\', '/')) : '';
		if (!SUPPORTED_LOCKFILES.includes(filename) && !SUPPORTED_MANIFESTS.includes(filename)) {
			errors.push(`lockfiles[${index}].filename must be one of ${[...SUPPORTED_LOCKFILES, ...SUPPORTED_MANIFESTS].join(', ')}`);
		} else if (typeof entry.content !== 'string') {
			errors.push(`lockfiles[${index}].content must be a string`);
		} else if (files.has(filename)) {
			errors.push(`lockfiles[${index}]: ${filename} sent twice (one application per lockfile)`);
		} else {
			files.set(filename, entry.content);
		}
	}
	if (errors.length === 0 && ![...files.keys()].some(filename => SUPPORTED_LOCKFILES.includes(filename))) errors.push(`lockfiles must hold one of ${SUPPORTED_LOCKFILES.join(', ')}`);
	return files;
}

function parseFiles(files, errors) {
	const manifests = Object.fromEntries([...files].filter(([filename]) => SUPPORTED_MANIFESTS.includes(filename)));
	const packages = [];
	for (const [filename, content] of files) {
		if (!SUPPORTED_LOCKFILES.includes(filename)) continue;
		const parsed = parseLockfile(filename, content, { manifests });
		if (parsed.errors) errors.push(...parsed.errors);
		else packages.push(...parsed.packages.map(item => ({ ecosystem: parsed.ecosystem, ...item })));
	}
	return packages;
}
