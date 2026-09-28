// run-tests.mjs: every suite that gates a release, one at a time (they share
// the mint's settings, each restoring what it found), then a summary. Exits 1
// if any suite fails; a suite that would SKIP fails too, so a green run is
// never a run of skips.
//
//   SHIP_URL=http://localhost:8080 URBAUTH_COOKIE='urbauth-~zod=0v…' npm run test:all
//   npm run test:all -- test-e2e test-p2pk      (just these)
//
// Needs: SHIP_URL and URBAUTH_COOKIE for a ship running %ecash and
// %ecash-services. The Lightning suites start their own mock LNbits on
// MOCK_PORT (default 3338) and need the mint's Lightning backend to be
// {type:"none"} (they could not restore a real backend's key). Suites that
// change settings run only against a ship on this machine unless
// ALLOW_DESTRUCTIVE=1.
import { spawnSync } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SUITES = [
  'test-vectors',            // offline: the client crypto vs the published vectors
  'test-admin-auth',         // the HTTP boundary of both agents
  'test-legacy-removed',
  'test-parse-robustness',
  'test-dashboards',
  'test-e2e',                // the mint (self method, no Lightning)
  'test-swap-security',
  'test-p2pk',
  'test-self-method',
  'test-admin',
  'test-restore',
  'test-ladder',
  'test-limits',             // the mint with a mock LNbits
  'test-lightning',
  'test-melt-fee',
  'test-melt-pending',
  'test-conformance',
  'test-cred',               // %ecash-services
  'test-services',
  'test-services-scope',
];

if (!process.env.SHIP_URL || !process.env.URBAUTH_COOKIE) {
  console.error('test:all needs SHIP_URL and URBAUTH_COOKIE');
  process.exit(1);
}
const suites = process.argv.length > 2 ? process.argv.slice(2).map((s) => s.replace(/\.mjs$/, '')) : SUITES;
const results = [];
for (const s of suites) {
  const r = spawnSync(process.execPath, [`${s}.mjs`], {
    cwd: dirname(fileURLToPath(import.meta.url)), env: { ...process.env, REQUIRE_AUTH: '1' },
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], maxBuffer: 1 << 26,
  });
  process.stdout.write(r.stdout ?? '');
  const [, p = 0, f = 0] = /(\d+) passed, (\d+) failed\s*$/.exec(r.stdout ?? '') ?? [];
  results.push({ s, ok: r.status === 0, p: +p, f: +f });
}
console.log('\n=== summary');
for (const { s, ok, p, f } of results) console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${s.padEnd(24)} ${p} passed, ${f} failed`);
const bad = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - bad} of ${results.length} suites passed; ${results.reduce((a, r) => a + r.p, 0)} checks passed, ${results.reduce((a, r) => a + r.f, 0)} failed`);
process.exit(bad ? 1 : 0);
