// NUT-10/11 spending conditions on a swap: a P2PK-locked proof spends only
// with enough distinct valid signatures; an unknown kind or sigflag is
// refused, never spent as a bearer proof.
import {
  run, check, refused, section, setSelf, keyset, selfMint, outputs, post, inputs, randomKey, pubHex, p2pkSign, randomHex,
} from './test-helpers.mjs';

const lock = (data, tags = []) => JSON.stringify(['P2PK', { nonce: randomHex(16), data, tags }]);

await run('p2pk', { auth: true, mutates: true }, async () => {
  await setSelf(true);
  const ks = await keyset();
  // spend: mint a 1-sat proof locked by secret, then swap it with these
  // signatures as its witness (none: no witness at all)
  async function spend(secret, sigs) {
    const [p] = await selfMint(ks, [1], [secret]);
    const input = { ...inputs([p])[0], ...(sigs ? { witness: JSON.stringify({ signatures: sigs }) } : {}) };
    return post('/v1/swap', { inputs: [input], outputs: outputs([1], ks.id).msgs });
  }
  const [a, b, c] = [randomKey(), randomKey(), randomKey()];

  section('single key');
  let s = lock(pubHex(a));
  check('the key\'s signature spends it', (await spend(s, [p2pkSign(s, a)])).status === 200);
  s = lock(pubHex(a));
  refused('no witness', await spend(s, null), 400, 'missing-witness-signatures');
  s = lock(pubHex(a));
  refused('another key\'s signature', await spend(s, [p2pkSign(s, b)]), 400, 'insufficient-p2pk-signatures');

  section('2-of-3 multisig');
  const multi = () => lock(pubHex(a), [['pubkeys', pubHex(b), pubHex(c)], ['n_sigs', '2']]);
  s = multi();
  check('two of the three keys spend it', (await spend(s, [p2pkSign(s, a), p2pkSign(s, c)])).status === 200);
  s = multi();
  refused('one key does not', await spend(s, [p2pkSign(s, a)]), 400, 'insufficient-p2pk-signatures');
  s = multi();
  refused('one key signing twice does not', await spend(s, [p2pkSign(s, a), p2pkSign(s, a)]), 400, 'insufficient-p2pk-signatures');
  // 02<x> and 03<x> are one Schnorr signer: they can't fill two slots
  const x = pubHex(a).slice(2);
  s = lock('02' + x, [['pubkeys', '03' + x], ['n_sigs', '2']]);
  refused('one key listed as both parities (02x, 03x) is one signer', await spend(s, [p2pkSign(s, a)]), 400, 'insufficient-p2pk-signatures');

  section('conditions the mint does not support are refused');
  s = JSON.stringify(['UNKNOWN_KIND', { nonce: randomHex(16), data: 'xyz', tags: [] }]);
  refused('an unknown kind is not spent as bearer', await spend(s, null), 400, 'unsupported-spending-condition');
  s = lock(pubHex(a), [['sigflag', 'SIG_ALL']]);
  refused('SIG_ALL', await spend(s, [p2pkSign(s, a)]), 400, 'unsupported-sigflag');
});
