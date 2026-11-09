// Software display names (Windows "Programs and Features" style) => the product tokens NVD uses
// in CPE names. Pure, no I/O.

const MAX_CANDIDATES = 3;
const ARCHITECTURES = new Set(['x64', 'x86', 'x86_64', 'amd64', 'arm64', 'aarch64', 'win64', 'win32', '64-bit', '32-bit', '64bit', '32bit']);
const NOISE = new Set(['update', 'version', 'release', 'setup', 'installer']);
const VENDOR_SUFFIXES = new Set(['inc', 'inc.', 'corp', 'corp.', 'corporation', 'ltd', 'ltd.', 'llc', 'gmbh', 'co', 'co.', 'foundation', 'project', 'software', 'technologies', 'team']);
const LOCALE = /^[a-z]{2}-[a-z]{2}$/;
const VERSION_LIKE = /^v?\d+\.\d/;

const isNoise = (token, version) => ARCHITECTURES.has(token) || NOISE.has(token) || LOCALE.test(token) || VERSION_LIKE.test(token) || token === version || token === '-';

// Text with every (...) and [...] part replaced by a space.
function stripBrackets(text) {
	let depth = 0;
	let kept = '';
	for (const character of text) {
		if (character === '(' || character === '[') depth += 1;
		else if ((character === ')' || character === ']') && depth > 0) depth -= 1;
		else if (depth === 0) kept += character;
		if (depth > 0) kept += ' ';
	}
	return kept;
}

// Lowercased words of a display name without bracketed parts, architecture, locale, version or filler.
function cleanWords(name, version) {
	// "Adobe Acrobat Reader DC - Français": what follows a spaced dash is an edition or a language.
	const [main] = name.toLowerCase().split(' - ');
	return stripBrackets(main).split(/[\s,]+/).filter(token => token && !isNoise(token, version?.toLowerCase()));
}

const vendorWords = vendor => new Set((vendor ?? '').toLowerCase().split(/[\s,]+/).filter(word => word && !VENDOR_SUFFIXES.has(word)));
const toToken = words => words.join('_');

// Ordered CPE product candidates: the name without the vendor's words first ("mozilla firefox" =>
// "firefox"), then the whole cleaned name, then the name without its first word (vendor-first
// display names reported without a vendor). Empty when nothing usable remains.
export function productCandidates({ name, vendor, version }) {
	const words = cleanWords(name, version);
	const ownWords = vendorWords(vendor);
	const withoutVendor = words.filter(word => !ownWords.has(word));
	const candidates = [toToken(withoutVendor), toToken(words), toToken(words.slice(1))].filter(Boolean);
	return [...new Set(candidates)].slice(0, MAX_CANDIDATES);
}
