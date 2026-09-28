// Benchmark: how long the mint takes to sign N outputs (each one blind
// signature and one DLEQ proof). Usage: node bench-crypto.mjs [N=32]
import { run, check, setSelf, keyset, outputs, post } from './test-helpers.mjs';

const N = Number(process.argv[2] || 32);

await run('bench', { auth: true, mutates: true }, async () => {
  await setSelf(true);
  const ks = await keyset();
  const q = (await post('/v1/mint/quote/self', { amount: N })).body;
  const o = outputs(Array(N).fill(1), ks.id);
  const t0 = performance.now();
  const m = await post('/v1/mint/self', { quote: q.quote, outputs: o.msgs });
  const dt = performance.now() - t0;
  check(`the mint signed all ${N}`, m.body?.signatures?.length === N, m.body ?? m.text);
  console.log(`mint ${N} outputs: ${dt.toFixed(0)} ms total, ${(dt / N).toFixed(1)} ms/output`);
});
