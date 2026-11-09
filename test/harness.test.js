import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const root = new URL('..', import.meta.url);

function runNode(code, environment) {
	return spawnSync(process.execPath, ['--input-type=module', '-e', code], { cwd: root, env: { ...process.env, ...environment }, encoding: 'utf8', timeout: 20_000 });
}

describe('test harness', () => {
	it('refuses a database whose name does not end with _test', () => {
		const result = runNode('await import("./test/helpers/database.js");', { DB_NAME: 'ariane' });
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /DB_NAME must end with _test/);
	});

	it('importing app.js binds no port and lets the process exit', () => {
		const result = runNode('const { default: app } = await import("./app.js"); const db = await import("./utils/database.js"); await db.default.end(); console.log(typeof app);', { PORT: '0' });
		assert.equal(result.status, 0, result.stderr);
		assert.equal(result.stdout.trim(), 'function');
	});
});
