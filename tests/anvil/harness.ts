/**
 * One anvil node in one Docker container, for the anchor scheduler's anvil
 * suite (Anchor §5, §6, §7.2, §11, §13).
 *
 * `startAnvil()` runs `ghcr.io/foundry-rs/foundry` (pinned; override with
 * TZUN_ANVIL_IMAGE) and `stop()` removes it with `docker rm -fv`, so no
 * container or volume outlives the suite. Each container is labelled with the
 * host and process that started it, and `startAnvil()` first removes the
 * containers a process on this host started and did not live to remove (a
 * jest run that was killed). When the test process itself runs in a
 * container, anvil joins that container's network and is reached by its
 * address there; otherwise its port is published on 127.0.0.1.
 *
 * WHEN IT RUNS. The default `pnpm test` leaves tests/anvil out;
 * `pnpm run test:anvil` (jest.anvil.config.js) runs it, and so does
 * .github/workflows/anvil.yml, path-filtered. Then `anvilAvailability()`
 * decides: never with TZUN_SKIP_ANVIL=1; under CI only with TZUN_ANVIL=1,
 * which that workflow sets, so no other job pulls the image; elsewhere,
 * wherever Docker runs containers.
 *
 * WHAT anvil's `finalized` IS. anvil answers the `finalized` tag with the
 * head minus twice `--slots-in-an-epoch` (32 by default; the harness uses 1,
 * so `finalized` is the head minus 2). That is a fixed depth anvil computes,
 * with no consensus behind it, and `evm_revert` can undo blocks below it. On
 * anvil the scheduler's rule "final means at or below the `finalized` tag" is
 * exercised as written; what it cannot show is finality itself, and the
 * suite's deep-revert case uses exactly that to show the history check
 * catching a "finalized" block that stopped being canonical.
 *
 * Keys: anvil's well-known development mnemonic, or random wallets funded with
 * `anvil_setBalance`. Nothing here is a real key.
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { HDNodeWallet, JsonRpcProvider, Mnemonic, Network, Wallet, toBeHex } from 'ethers';

export const ANVIL_IMAGE = process.env.TZUN_ANVIL_IMAGE ?? 'ghcr.io/foundry-rs/foundry:v1.5.1';
export const ANVIL_CHAIN_ID = 31337n;
/** `--slots-in-an-epoch 1`: anvil's `finalized` tag is the head minus 2. */
export const ANVIL_FINALIZED_DEPTH = 2;
const DEV_MNEMONIC = 'test test test test test test test test test test test junk';

function docker(args: string[], timeoutMs = 120_000): { ok: boolean; stdout: string; stderr: string } {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: timeoutMs });
  return { ok: r.status === 0, stdout: (r.stdout ?? '').trim(), stderr: (r.stderr ?? '').trim() || (r.error?.message ?? '') };
}

/** Whether Docker can run containers here, and why not when it cannot. */
export function dockerAvailability(): { ok: true } | { ok: false; reason: string } {
  const info = docker(['info', '--format', '{{.ServerVersion}}'], 20_000);
  if (!info.ok) return { ok: false, reason: info.stderr.split('\n')[0] || 'docker info failed' };
  return { ok: true };
}

/** Whether the anvil suite runs in this environment (see WHEN IT RUNS), and why not when it does not. */
export function anvilAvailability(env: NodeJS.ProcessEnv = process.env): { ok: true } | { ok: false; reason: string } {
  if (env.TZUN_SKIP_ANVIL === '1') return { ok: false, reason: 'TZUN_SKIP_ANVIL=1' };
  if (env.CI && env.CI !== 'false' && env.TZUN_ANVIL !== '1') {
    return { ok: false, reason: 'CI is set and TZUN_ANVIL=1 is not: a CI job runs the anvil suite only when it asks for it' };
  }
  return dockerAvailability();
}

const OWNER_LABEL = 'tzun-anvil-owner';

/** Whether process `pid` is alive on this host. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/**
 * Remove the suite's containers that a process on this host started and that
 * outlived it. A container of a live process, or of another host, is left alone.
 */
export function removeStaleAnvils(): string[] {
  const list = docker(['ps', '-a', '--filter', 'label=tzun-anvil-suite=1', '--format', `{{.ID}} {{.Label "${OWNER_LABEL}"}}`], 30_000);
  if (!list.ok) return [];
  const removed: string[] = [];
  for (const line of list.stdout.split('\n').filter(Boolean)) {
    const [id, owner = ''] = line.split(' ');
    const sep = owner.lastIndexOf(':');
    const host = owner.slice(0, sep);
    const pid = Number(owner.slice(sep + 1));
    if (sep <= 0 || host !== hostname() || !Number.isSafeInteger(pid) || alive(pid)) continue;
    if (docker(['rm', '-fv', id], 60_000).ok) removed.push(id);
  }
  return removed;
}

export interface AnvilNode {
  rpcUrl: string;
  provider: JsonRpcProvider;
  rpc<T = unknown>(method: string, params?: unknown[]): Promise<T>;
  /** Mine `n` blocks. */
  mine(n?: number): Promise<void>;
  setAutomine(on: boolean): Promise<void>;
  /** The base fee of the next block, in wei. */
  setNextBaseFee(wei: bigint): Promise<void>;
  setBalance(address: string, wei: bigint): Promise<void>;
  /** A random wallet with `wei` in it. */
  fundedWallet(wei?: bigint): Promise<Wallet>;
  /** anvil's development account `i`. */
  devAccount(i: number): HDNodeWallet;
  head(): Promise<number>;
  finalized(): Promise<number>;
  stop(): Promise<void>;
}

/** The first Docker network this process's own container is on, or null when it is not in a container. */
function ownNetwork(): string | null {
  const r = docker(['inspect', hostname(), '--format', '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}'], 20_000);
  if (!r.ok) return null;
  return r.stdout.split(/\s+/).filter(Boolean)[0] ?? null;
}

export async function startAnvil(): Promise<AnvilNode> {
  removeStaleAnvils();
  const name = `tzun-anvil-${randomBytes(4).toString('hex')}`;
  const network = ownNetwork();
  const placement = network ? ['--network', network] : ['-p', '127.0.0.1::8545'];
  const run = docker(
    [
      'run', '-d', '--rm', '--name', name, '--label', 'tzun-anvil-suite=1',
      '--label', `${OWNER_LABEL}=${hostname()}:${process.pid}`, ...placement,
      '--entrypoint', 'anvil', ANVIL_IMAGE,
      '--host', '0.0.0.0', '--chain-id', ANVIL_CHAIN_ID.toString(), '--slots-in-an-epoch', '1', '--silent',
    ],
    300_000,
  );
  if (!run.ok) throw new Error(`could not start anvil (${ANVIL_IMAGE}): ${run.stderr}`);
  const remove = async (): Promise<void> => {
    docker(['rm', '-fv', name], 60_000);
  };
  try {
    let rpcUrl: string;
    if (network) {
      const ip = docker(['inspect', name, '--format', `{{(index .NetworkSettings.Networks "${network}").IPAddress}}`]).stdout;
      rpcUrl = `http://${ip}:8545`;
    } else {
      const port = docker(['port', name, '8545/tcp']).stdout.split('\n')[0].split(':').pop();
      rpcUrl = `http://127.0.0.1:${port}`;
    }
    const net = Network.from(ANVIL_CHAIN_ID);
    const provider = new JsonRpcProvider(rpcUrl, net, { staticNetwork: net, batchMaxCount: 1, cacheTimeout: -1 });
    const rpc = <T>(method: string, params: unknown[] = []): Promise<T> => provider.send(method, params) as Promise<T>;
    const deadline = Date.now() + 60_000;
    for (;;) {
      try {
        if (BigInt(await rpc<string>('eth_chainId')) === ANVIL_CHAIN_ID) break;
      } catch {
        /* not up yet */
      }
      if (Date.now() > deadline) throw new Error('anvil did not answer within 60 s');
      await new Promise((r) => setTimeout(r, 250));
    }
    const node: AnvilNode = {
      rpcUrl,
      provider,
      rpc,
      async mine(n = 1) {
        await rpc('anvil_mine', [toBeHex(n)]);
      },
      async setAutomine(on) {
        await rpc('evm_setAutomine', [on]);
      },
      async setNextBaseFee(wei) {
        await rpc('anvil_setNextBlockBaseFeePerGas', [toBeHex(wei)]);
      },
      async setBalance(address, wei) {
        await rpc('anvil_setBalance', [address, toBeHex(wei)]);
      },
      async fundedWallet(wei = 10n ** 18n) {
        const w = Wallet.createRandom() as unknown as Wallet;
        await node.setBalance(w.address, wei);
        return w;
      },
      devAccount(i) {
        return HDNodeWallet.fromMnemonic(Mnemonic.fromPhrase(DEV_MNEMONIC), `m/44'/60'/0'/0/${i}`);
      },
      async head() {
        return Number(BigInt(await rpc<string>('eth_blockNumber')));
      },
      async finalized() {
        const b = await rpc<{ number: string } | null>('eth_getBlockByNumber', ['finalized', false]);
        return b ? Number(BigInt(b.number)) : -1;
      },
      async stop() {
        provider.destroy();
        await remove();
      },
    };
    return node;
  } catch (err) {
    await remove();
    throw err;
  }
}
