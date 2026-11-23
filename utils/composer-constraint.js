import { compareVersions } from './cpe-match.js';

// Does a locked Composer version satisfy an advisory's `affectedVersions` constraint? Packagist
// writes them as an OR (`|`) of ANDs (`,` or space) of `>=`, `>`, `<=`, `<`, `=`, `!=` comparisons
// (`>=7.4.0,<7.4.22|>=8.0.0,<8.1.10`). Returns true, false, or undefined when the version or the
// constraint is in a form this evaluator does not read (branch versions, `^`, `~`, wildcards):
// the caller never counts undefined as affected.
const COMPARISON = /^(>=|<=|>|<|==|=|!=)?\s*v?(\d[\w.+-]*)$/;
const RELEASE_VERSION = /^v?\d[\w.+-]*$/;

const TESTS = {
	'>=': order => order >= 0,
	'>': order => order > 0,
	'<=': order => order <= 0,
	'<': order => order < 0,
	'!=': order => order !== 0,
	'=': order => order === 0,
	'==': order => order === 0
};

function evaluateGroup(version, group) {
	const parts = group.split(/[\s,]+/).filter(Boolean);
	if (parts.length === 0) return;
	let result = true;
	for (const part of parts) {
		const match = COMPARISON.exec(part);
		if (!match) return;
		result &&= TESTS[match[1] ?? '='](compareVersions(version, match[2]));
	}
	return result;
}

export function satisfies(version, constraint) {
	if (!RELEASE_VERSION.test(String(version)) || typeof constraint !== 'string') return;
	const normalized = version.replace(/^v/, '');
	let unreadable = false;
	for (const group of constraint.split('|')) {
		const result = evaluateGroup(normalized, group.trim());
		if (result === true) return true;
		if (result === undefined) unreadable = true;
	}
	return unreadable ? undefined : false;
}
