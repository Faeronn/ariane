import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { productCandidates } from '../utils/software-name.js';

// Display names as Windows reports them, with the first CPE product expected.
const CASES = [
	['Mozilla Firefox (x64 fr)', 'mozilla', '115.0', 'firefox'],
	['Mozilla Firefox (x64 en-US)', '', '115.0', 'mozilla_firefox'],
	['7-Zip 23.01 (x64)', 'igor pavlov', '23.01', '7-zip'],
	['Google Chrome', 'google llc', '122.0.6261.112', 'chrome'],
	['VLC media player', 'videolan', '3.0.20', 'vlc_media_player'],
	['Python 3.12.1 (64-bit)', 'python software foundation', '3.12.1', 'python'],
	['Git', 'the git development community', '2.43.0', 'git'],
	['PuTTY release 0.80 (64-bit)', 'simon tatham', '0.80', 'putty'],
	['WinSCP 6.1.2', 'martin prikryl', '6.1.2', 'winscp'],
	['Microsoft Teams', 'microsoft corporation', '1.6.0', 'teams'],
	['Adobe Acrobat Reader DC - Français', 'adobe', '23.008', 'acrobat_reader_dc'],
	['Wireshark 4.2.2 x64', 'the wireshark developer community', '4.2.2', 'wireshark'],
	['Node.js', 'node.js foundation', '20.11.0', 'node.js'],
	['KeePass Password Safe 2.55', 'dominik reichl', '2.55', 'keepass_password_safe'],
	['openssl', 'openssl', '3.0.0', 'openssl'],
	['libssl3', 'debian', '3.0.11-1~deb12u2', 'libssl3']
];

describe('productCandidates', () => {
	for (const [name, vendor, version, expected] of CASES) {
		it(`"${name}" => ${expected} first`, () => {
			assert.equal(productCandidates({ name, vendor, version })[0], expected);
		});
	}

	it('falls back to the name without its first word when no vendor is given', () => {
		assert.deepEqual(productCandidates({ name: 'Mozilla Firefox (x64 en-US)', version: '115.0' }), ['mozilla_firefox', 'firefox']);
	});

	it('returns nothing for a name made only of noise', () => {
		assert.deepEqual(productCandidates({ name: '(x64) 1.2.3', vendor: '', version: '1.2.3' }), []);
	});

	it('never returns more than 3 distinct candidates', () => {
		const candidates = productCandidates({ name: 'Acme Super Tool Pro', vendor: 'acme', version: '1.0' });
		assert.ok(candidates.length <= 3);
		assert.equal(new Set(candidates).size, candidates.length);
	});
});
