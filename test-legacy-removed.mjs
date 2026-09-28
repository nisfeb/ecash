// The pre-Cashu mint and melt routes, which minted without a quote, stay gone.
import { run, refused, post } from './test-helpers.mjs';

await run('legacy-removed', {}, async () => {
  refused('POST /apps/ecash/mint', await post('/apps/ecash/mint', { outputs: [] }), 404, 'not-found');
  refused('POST /apps/ecash/melt', await post('/apps/ecash/melt', { outputs: [] }), 404, 'not-found');
});
