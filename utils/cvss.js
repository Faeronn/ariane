// CVSS v3.0 / v3.1 base score from a vector string, per the FIRST specification
// (https://www.first.org/cvss/v3.1/specification-document, section 7). Pure, no I/O.

const WEIGHTS = {
	AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
	AC: { L: 0.77, H: 0.44 },
	UI: { N: 0.85, R: 0.62 },
	CIA: { H: 0.56, L: 0.22, N: 0 }
};
// Privileges Required weighs more when the scope changes.
const PRIVILEGES = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } };

// v3.1 Roundup: smallest one-decimal number >= value, computed on integers to avoid float drift.
function roundUp31(value) {
	const integer = Math.round(value * 100_000);
	return integer % 10_000 === 0 ? integer / 100_000 : (Math.floor(integer / 10_000) + 1) / 10;
}
const roundUp30 = value => Math.ceil(value * 10) / 10;

// `CVSS:3.1/AV:N/AC:L/...` => { version: '3.1', metrics: { AV: 'N', ... } }, or undefined.
function parseVector(vector) {
	const match = /^CVSS:(3\.[01])\/(.+)$/.exec(String(vector));
	if (!match) return;
	const metrics = Object.fromEntries(match[2].split('/').map(part => part.split(':')));
	return { version: match[1], metrics };
}

// Base score (0.0 to 10.0) of a CVSS v3.x vector; undefined for another version or a malformed one.
export function cvssBaseScore(vector) {
	const parsed = parseVector(vector);
	if (!parsed) return;
	const { AV, AC, PR, UI, S, C, I, A } = parsed.metrics;
	const scope = PRIVILEGES[S];
	const weights = [WEIGHTS.AV[AV], WEIGHTS.AC[AC], scope?.[PR], WEIGHTS.UI[UI], WEIGHTS.CIA[C], WEIGHTS.CIA[I], WEIGHTS.CIA[A]];
	if (weights.includes(undefined)) return;
	const [av, ac, pr, ui, c, index, a] = weights;

	const impactSubScore = 1 - ((1 - c) * (1 - index) * (1 - a));
	const impact = S === 'U' ? 6.42 * impactSubScore : (7.52 * (impactSubScore - 0.029)) - (3.25 * ((impactSubScore - 0.02) ** 15));
	if (impact <= 0) return 0;
	const exploitability = 8.22 * av * ac * pr * ui;
	const roundUp = parsed.version === '3.1' ? roundUp31 : roundUp30;
	return S === 'U' ? roundUp(Math.min(impact + exploitability, 10)) : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

// Qualitative rating of a score (FIRST table 14); undefined for 0 (None) or no score.
export function severityOfScore(score) {
	if (!score) return;
	if (score >= 9) return 'CRITICAL';
	if (score >= 7) return 'HIGH';
	if (score >= 4) return 'MEDIUM';
	return 'LOW';
}
