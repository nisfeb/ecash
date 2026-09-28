// Both admin dashboards load under their CSP: a fresh nonce on each page's
// own script and no inline event handlers, which that CSP would block (the
// services dashboard sat dead for months that way with nothing checking it).
import { run, check, refused, section, call } from './test-helpers.mjs';

await run('dashboards', { auth: true }, async () => {
  for (const page of ['/apps/ecash/admin', '/apps/ecash-services/admin']) {
    section(page);
    refused('without a session: 401', await call(page), 401, 'unauthorized');
    const [a, b] = [await call(page, { auth: true }), await call(page, { auth: true })];
    check('with one: 200 html', a.status === 200 && (a.headers.get('content-type') ?? '').startsWith('text/html'), a.status);
    const csp = a.headers.get('content-security-policy') ?? '';
    const nonce = /script-src[^;]*'nonce-([0-9a-f]{32})'/.exec(csp)?.[1];
    check('the CSP allows scripts only by nonce', !!nonce && !/script-src[^;]*'unsafe-inline'/.test(csp), csp);
    const scripts = [...a.text.matchAll(/<script\b[^>]*>/g)].map((m) => m[0]);
    check('every script tag carries that nonce', scripts.length > 0 && scripts.every((s) => s.includes(`nonce="${nonce}"`)), scripts);
    check('the nonce is fresh on each load', nonce !== /'nonce-([0-9a-f]{32})'/.exec(b.headers.get('content-security-policy') ?? '')?.[1]);
    // an on*= attribute in markup, or in markup the script builds
    const inline = [...a.text.matchAll(/<[a-z][^>]*\son[a-z]+\s*=/gi)].map((m) => m[0].slice(0, 80));
    check('no inline event handlers (the CSP would block them)', inline.length === 0, inline);
  }
});
