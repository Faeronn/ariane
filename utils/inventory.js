import sanitizeInput from './sanitizer.js';

export const MAX_SOFTWARE_ENTRIES = 10_000;
const MAX_ERRORS = 20;
const OS_FAMILIES = new Set(['linux', 'windows']);
const LIMITS = { hostname: 255, osVersion: 255, vendor: 255, name: 255, version: 100 };

// Validate and normalize an agent inventory payload:
// { hostname?, osFamily, osVersion?, collectedAt?, software: [{ name, version?, vendor? }] }.
// Returns { errors } when invalid, else { inventory } with trimmed, sanitized, deduplicated entries
// whose vendor and name are lowercased, since they are the keys used for CPE matching.
export function validateInventory(payload) {
	const errors = [];
	if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { errors: ['body must be a JSON object'] };

	const hostname = readString(payload, 'hostname', errors);
	if (hostname && !/^[\w.-]+$/.test(hostname)) errors.push('hostname has invalid characters');

	const osFamily = readString(payload, 'osFamily', errors)?.toLowerCase();
	if (!OS_FAMILIES.has(osFamily)) errors.push('osFamily must be linux or windows');

	const osVersion = readString(payload, 'osVersion', errors);
	const collectedAt = readDate(payload.collectedAt, errors);
	const software = readSoftware(payload.software, errors);

	if (errors.length > 0) return { errors: errors.slice(0, MAX_ERRORS) };
	return { inventory: { hostname, osFamily, osVersion, collectedAt, software } };
}

function readSoftware(entries, errors) {
	if (!Array.isArray(entries)) {
		errors.push('software must be an array');
		return [];
	}
	if (entries.length > MAX_SOFTWARE_ENTRIES) {
		errors.push(`software has more than ${MAX_SOFTWARE_ENTRIES} entries`);
		return [];
	}

	const unique = new Map();
	for (const [index, entry] of entries.entries()) {
		if (!entry || typeof entry !== 'object') {
			errors.push(`software[${index}] must be an object`);
			continue;
		}
		const name = readString(entry, 'name', errors, `software[${index}].`)?.toLowerCase();
		if (!name) errors.push(`software[${index}].name is required`);
		const vendor = (readString(entry, 'vendor', errors, `software[${index}].`) ?? '').toLowerCase();
		const version = readString(entry, 'version', errors, `software[${index}].`) ?? '';
		if (name) unique.set(JSON.stringify([vendor, name, version]), { vendor, name, version });
	}
	return [...unique.values()];
}

function readString(source, field, errors, prefix = '') {
	const value = source[field];
	if (value === undefined || value === null) return;
	if (typeof value !== 'string') {
		errors.push(`${prefix}${field} must be a string`);
		return;
	}
	const cleaned = sanitizeInput(value).trim();
	if (cleaned.length > LIMITS[field]) errors.push(`${prefix}${field} is longer than ${LIMITS[field]} characters`);
	return cleaned || undefined;
}

function readDate(value, errors) {
	if (value === undefined || value === null) return new Date();
	const date = typeof value === 'string' ? new Date(value) : new Date(Number.NaN);
	if (Number.isNaN(date.getTime())) {
		errors.push('collectedAt must be an ISO 8601 date');
		return;
	}
	return date;
}
