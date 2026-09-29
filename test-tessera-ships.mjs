// %tessera between ships, over Ames: an issuer, a holder on its policy, and
// a third ship that is a verifier but not on the policy. The holder gets
// and uses tokens (with a forward to the issuer's %tessera-demo guestbook),
// the third ship checks and burns one it was shown, and the holder hands
// tokens over, which wait as an offer until the third ship accepts (a
// refresh at the issuer) or declines them.
//
//   SHIP_URL, URBAUTH_COOKIE      the issuer
//   HOLDER_URL, HOLDER_COOKIE     the holder
//   THIRD_URL, THIRD_COOKIE       the third ship
//
// Each runs %tessera; the issuer also runs %tessera-demo
// (|rein %tessera [& %tessera-demo]). Not in run-tests: it needs three ships.
import { run, check, section, onCleanup, poll, TAG } from './test-helpers.mjs';

const at = (url, cookie) => ({ url: (url || '').replace(/\/+$/, ''), cookie });
const I = at(process.env.SHIP_URL, process.env.URBAUTH_COOKIE);
const H = at(process.env.HOLDER_URL, process.env.HOLDER_COOKIE);
const T = at(process.env.THIRD_URL, process.env.THIRD_COOKIE);

// api: a ship's %tessera admin API; a body makes it a POST
async function api(s, path, body) {
  const r = await fetch(`${s.url}/apps/tessera/api${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { cookie: s.cookie, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: r.status, body: json, text };
}
const refusal = (label, r, detail) => check(label, r.status === 400 && r.body?.detail === detail, { status: r.status, body: r.body ?? r.text });
const count = async (s, issuer, service) =>
  (await api(s, '/wallet')).body?.wallet?.find((w) => w.issuer === issuer && w.service === service)?.count ?? 0;
const offered = async (s, from, service) =>
  (await api(s, '/wallet')).body?.offers?.find((o) => o.from === from && o.service === service)?.count ?? 0;

await run('tessera-ships', { auth: true }, async () => {
  if (!H.url || !H.cookie || !T.url || !T.cookie) throw new Error('set HOLDER_URL, HOLDER_COOKIE, THIRD_URL and THIRD_COOKIE');
  const name = async (s) => (await fetch(`${s.url}/~/name`, { headers: { cookie: s.cookie } })).text();
  const [iss, hol, thi] = await Promise.all([name(I), name(H), name(T)]);
  const svc = `${TAG}-club`;
  onCleanup(() => api(I, '/services/deactivate', { name: svc }));
  const w = (s, act, body) => api(s, `/wallet/${act}`, { issuer: iss, service: svc, ...body });

  section(`${iss} issues to ${hol}, not to ${thi}`);
  const c = await api(I, '/services/create', { name: svc, title: 'Club', ships: [hol], verifiers: [thi], quota: { n: 4, per: 3600 } });
  check('a service for one ship, with a verifier ship', c.body?.ships?.join() === hol && c.body.verifiers?.join() === thi, c.body);
  const g = await w(H, 'get', { n: 3 });
  check('the holder gets 3 (unblinded, their DLEQ proofs checked)', g.body?.done === 3, g.body ?? g.text);
  check('its wallet holds 3', (await count(H, iss, svc)) === 3);
  refusal('the third ship is not on the policy', await w(T, 'get', { n: 1 }), 'not-allowed');

  section('use, and the quota');
  const u = await w(H, 'use', {});
  check('the holder uses one: fresh', u.body?.fresh === true, u.body ?? u.text);
  check('it is gone from the wallet', (await count(H, iss, svc)) === 2);
  refusal('3 issued of a quota of 4: 2 more is too many', await w(H, 'get', { n: 2 }), 'quota-exceeded');
  check('1 more is not', (await w(H, 'get', { n: 1 })).body?.done === 1);
  const listed = (await api(I, '/services')).body?.services?.find((s) => s.name === svc);
  check('the issuer counts 4 issued, 1 redeemed', listed?.issued === 4 && listed.redeemed === 1, listed);

  section(`${thi} as a verifier`);
  const tk = (await w(H, 'take', {})).body?.token;
  check('the holder takes a token out as an authA string', tk?.startsWith('authA') && (await count(H, iss, svc)) === 2, tk);
  const look = await w(T, 'ask', { token: tk, burn: false });
  check('the third ship checks it: fresh', look.body?.fresh === true, look.body ?? look.text);
  check('burns it: fresh', (await w(T, 'ask', { token: tk, burn: true })).body?.fresh === true);
  check('and again: spent', (await w(T, 'ask', { token: tk, burn: true })).body?.fresh === false);
  refusal('the holder is no verifier', await w(H, 'ask', { token: tk, burn: false }), 'not-a-verifier');

  section('refusals give tokens back');
  await api(I, '/services/deactivate', { name: svc });
  refusal('a use at a switched-off service', await w(H, 'use', {}), 'service-inactive');
  check('the token is back', (await count(H, iss, svc)) === 2);
  await api(I, '/services/activate', { name: svc });
  refusal('no tokens of a service', await api(H, '/wallet/use', { issuer: iss, service: `${TAG}-none` }), 'no-tokens');
  refusal('a bad issuer', await api(H, '/wallet/get', { issuer: 'lyd', service: svc, n: 1 }), 'invalid-issuer');

  section('hand-over');
  const gv = await w(H, 'give', { to: thi, n: 1 });
  check('the holder gives one to the third ship', gv.body?.done === 1 && (await count(H, iss, svc)) === 1, gv.body ?? gv.text);
  check('where it waits as an offer, not yet held', (await offered(T, hol, svc)) === 1 && (await count(T, iss, svc)) === 0);
  const acc = await w(T, 'accept', { from: hol });
  check('the third ship accepts it: refreshed at the issuer, and held', acc.body?.done === 1 && (await count(T, iss, svc)) === 1, acc.body ?? acc.text);
  check('the offer is gone', (await offered(T, hol, svc)) === 0);
  check('and uses it, though not on the policy', (await w(T, 'use', {})).body?.fresh === true);
  await w(H, 'give', { to: thi, n: 1 });
  const dec = await w(T, 'decline', { from: hol });
  check('an offer declined is dropped', dec.body?.done === 1 && (await offered(T, hol, svc)) === 0 && (await count(T, iss, svc)) === 0, dec.body ?? dec.text);
  refusal('nothing is left to accept', await w(T, 'accept', { from: hol }), 'no-offer');
  refusal('the holder cannot give more than it holds', await w(H, 'give', { to: thi, n: 1 }), 'not-enough-tokens');

  section('a forward to an agent on the issuer');
  const gb = 'guestbook';
  const gbf = { ships: [hol], agents: ['tessera-demo', 'not-running-here'] };
  const made = await api(I, '/services/create', { name: gb, title: 'Guestbook', ...gbf });
  if (made.status === 409) {
    await api(I, '/services/update', { name: gb, open: false, ...gbf });
    await api(I, '/services/activate', { name: gb });
  }
  const wg = (s, act, body) => api(s, `/wallet/${act}`, { issuer: iss, service: gb, ...body });
  check('the holder gets a guestbook token', (await wg(H, 'get', { n: 1 })).body?.done === 1);
  const before = await count(H, iss, gb);
  refusal('the holder cannot pick an agent the service does not name', await wg(H, 'use', { agent: 'hood', data: {} }), 'agent-not-allowed');
  refusal('nor one that is not running', await wg(H, 'use', { agent: 'not-running-here', data: {} }), 'agent-not-running');
  check('neither spent the token', (await count(H, iss, gb)) === before);
  const text = `hello ${TAG}`;
  const bad = await wg(H, 'use', { agent: 'tessera-demo', data: { text: '' } });
  check('the guestbook refuses an empty post: the token is not used', bad.body?.detail === 'forward-refused', bad.body ?? bad.text);
  check('and is back in the wallet', (await count(H, iss, gb)) === before);
  const ok = await wg(H, 'use', { agent: 'tessera-demo', data: { text } });
  check('a post: fresh', ok.body?.fresh === true, ok.body ?? ok.text);
  const posts = await (await fetch(`${I.url}/apps/tessera-demo/posts`)).json();
  check('the guestbook shows it, from the holder', posts.some((p) => p.text === text && p.who === hol), posts.slice(0, 3));

});
