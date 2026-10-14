/**
 * Jest setup (setupFilesAfterEnv): no unit test reaches a live host.
 *
 * Installs the guard from tests/ts/helpers/no-live-network.ts before any test
 * file's own code runs, and fails — by test name, quoting the URL — any test
 * during which a non-loopback fetch was refused, even when the code under test
 * caught the refusal and carried on. See the helper for why both halves are
 * needed. RUN_INTEGRATION_TESTS=true switches the guard off for the run.
 */
import {
  drainRefusals,
  installNoLiveNetworkGuard,
  liveNetworkAllowed,
} from '../helpers/no-live-network';

installNoLiveNetworkGuard();

afterEach(() => {
  const refused = drainRefusals();
  if (refused.length === 0 || liveNetworkAllowed()) return;
  const lines = refused.map((r) => `  - ${r.url}`);
  throw new Error(
    `${refused.length} fetch call(s) to a non-loopback host were refused during this test. ` +
      `The code under test may have swallowed the refusal — a capture() ` +
      `in a production mode stores the record 'pending' without its timestamp — so ` +
      `this hook is what makes it fail:\n${lines.join('\n')}\n` +
      `Stub fetch, capture in mode: 'dev', or gate the test on RUN_INTEGRATION_TESTS=true.`,
  );
});
