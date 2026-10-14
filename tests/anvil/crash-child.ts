/**
 * A scheduler process that dies right after it broadcasts, for the anvil suite.
 *
 *   tsx tests/anvil/crash-child.ts <sqlite file> <rpc url> <anvil dev account index> [privateKey|signer]
 *
 * It forces one epoch and SIGKILLs itself once the node has the signed
 * transaction and before the outcome is recorded: no finally block, no
 * clean close. What the store holds afterwards is what a crash leaves.
 */
import { HDNodeWallet, Mnemonic } from 'ethers';
import { SqliteStorageAdapter } from '../../src/storage/sqlite';
import { createAnchorScheduler } from '../../src/anchoring';
import { ClosureSigner } from '../ts/helpers/closure-signer';

async function main(): Promise<void> {
  const [file, rpcUrl, index, kind = 'privateKey'] = process.argv.slice(2);
  const publisher = HDNodeWallet.fromMnemonic(
    Mnemonic.fromPhrase('test test test test test test test test test test test junk'),
    `m/44'/60'/0'/0/${Number(index)}`,
  );
  const scheduler = await createAnchorScheduler({
    storage: new SqliteStorageAdapter(file),
    config: {
      publishers: {
        evm:
          kind === 'signer'
            ? { rpcUrl, signer: new ClosureSigner(publisher.privateKey), chain: 'eip155:31337' }
            : { rpcUrl, privateKey: publisher.privateKey, chain: 'eip155:31337' },
      },
    },
    expectation: {},
    holderId: 'crashing-process',
    tuning: { leaseTtlMs: 1_000 },
    testHooks: {
      afterBroadcast: () => {
        process.stdout.write('broadcast\n');
        process.kill(process.pid, 'SIGKILL');
      },
    },
  });
  await scheduler.anchorNow({ force: true });
  process.stdout.write('pass finished without the hook\n');
}

main().catch((err) => {
  process.stderr.write(`${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
