/**
 * The publisher's `rpcUrl` is a secret: providers such as Infura and Alchemy
 * put the API key in its path. ethers writes the request URL into the
 * message of every HTTP failure (`info.requestUrl`), and before this suite
 * that message reached `anchorNow()`'s rejection, `getAnchorState().lastError`,
 * the scheduled loop's `anchor_pass_failed` event and the scanner's console
 * output (the whole-candidate review's rpcurl-leak and leak-e2e probes).
 *
 * A node on loopback answers every request with an HTTP error, as a provider
 * does for an exhausted or revoked key, and no output may name the key.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Wallet } from 'ethers';
import { JsonRpcEvmChain, EvmRpcError, classifyBroadcastError, rpcErrorText } from '../../src/anchoring/evm-chain';
import { createAnchorScheduler } from '../../src/anchoring';
import { Tzun } from '../../src/sdk/index';

const KEY = 'SECRET_PROJECT_KEY_abc123';
const SEPOLIA = 'eip155:11155111';

/** Everything an error carries that a log line, a JSON body or a console could print. */
function everythingIn(value: unknown): string {
  let json = '';
  try {
    json = JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  } catch {
    /* a cycle: inspect still prints it */
  }
  return `${String(value)}\n${json}\n${inspect(value, { depth: 8, showHidden: true })}`;
}

/** A node on loopback that answers every request with `status`, and the rpcUrl that reaches it with the key in its path. */
async function failingNode(status: number): Promise<{ rpcUrl: string; close: () => Promise<void> }> {
  const server = http.createServer((_req, res) => {
    res.writeHead(status, { 'content-type': 'text/plain' });
    res.end('upstream says no');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    rpcUrl: `http://127.0.0.1:${port}/v3/${KEY}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe.each([503, 401])('JsonRpcEvmChain against a node answering HTTP %i', (status) => {
  let node: Awaited<ReturnType<typeof failingNode>>;
  let chain: JsonRpcEvmChain;

  beforeAll(async () => {
    node = await failingNode(status);
    chain = new JsonRpcEvmChain(node.rpcUrl, 11155111n, { timeoutMs: 3_000 });
  });
  afterAll(async () => {
    chain.close();
    await node.close();
  });

  const hash = '0x' + '11'.repeat(32);
  const address = '0x' + '22'.repeat(20);
  it.each([
    ['chainId', () => chain.chainId()],
    ['transactionCount', () => chain.transactionCount(address, 'pending')],
    ['balance', () => chain.balance(address)],
    ['fees', () => chain.fees()],
    ['receipt', () => chain.receipt(hash)],
    ['transaction', () => chain.transaction(hash)],
    ['finalizedBlockNumber', () => chain.finalizedBlockNumber()],
    ['canonicalBlock', () => chain.canonicalBlock(1)],
    ['blockMaterial', () => chain.blockMaterial(1)],
  ] as Array<[string, () => Promise<unknown>]>)('%s rejects with the status and without the URL', async (_name, call) => {
    const err = await call().then(
      () => {
        throw new Error('expected a rejection');
      },
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(EvmRpcError);
    const all = everythingIn(err);
    expect(all).not.toContain(KEY);
    expect(all).not.toContain(node.rpcUrl);
    expect((err as Error).message).toContain(String(status));
    expect(err).toMatchObject({ code: 'SERVER_ERROR', status });
  });

  it('broadcast sorts the failure as before, and its detail names no URL', async () => {
    const result = await chain.broadcast('0x02');
    expect(result).toMatchObject({ outcome: 'unknown', reason: 'unreachable' });
    expect(everythingIn(result)).not.toContain(KEY);
  });
});

describe('rpcErrorText and EvmRpcError', () => {
  /** An error shaped as ethers throws it for an HTTP failure. */
  const ethersServerError = () =>
    Object.assign(
      new Error(
        `server response 503 Service Unavailable (request={  }, response={  }, error=null, info={ "requestUrl": "https://sepolia.infura.io/v3/${KEY}", "responseBody": "upstream says no", "responseStatus": "503 Service Unavailable" }, code=SERVER_ERROR, version=6.15.0)`,
      ),
      {
        code: 'SERVER_ERROR',
        shortMessage: 'server response 503 Service Unavailable',
        info: { requestUrl: `https://sepolia.infura.io/v3/${KEY}`, responseBody: 'upstream says no' },
        request: { url: `https://sepolia.infura.io/v3/${KEY}` },
        response: { statusCode: 503 },
      },
    );

  it("takes ethers' short message, and the node's own message when there is one", () => {
    expect(rpcErrorText(ethersServerError())).toBe('server response 503 Service Unavailable');
    expect(rpcErrorText({ code: 'UNKNOWN_ERROR', shortMessage: 'could not coalesce error', error: { code: -32000, message: 'header not found' } })).toBe(
      'could not coalesce error: header not found',
    );
  });

  it('replaces any URL left in the text, for a client that is not ethers', () => {
    expect(rpcErrorText(new Error(`fetch https://user:pass@eth.example/v2/${KEY}?x=1 failed`))).toBe('fetch <url> failed');
    expect(rpcErrorText('wss://node.example/ws/abc down')).toBe('<url> down');
  });

  it('keeps what classifyBroadcastError reads, and nothing that holds the URL', () => {
    const wrapped = new EvmRpcError(ethersServerError());
    expect(everythingIn(wrapped)).not.toContain(KEY);
    expect(wrapped).toMatchObject({ name: 'EvmRpcError', code: 'SERVER_ERROR', status: 503, shortMessage: 'server response 503 Service Unavailable' });
    const rpc = { code: 'UNKNOWN_ERROR', shortMessage: 'could not coalesce error', error: { code: -32000, message: 'nonce too low: next nonce 4' } };
    expect(classifyBroadcastError(new EvmRpcError(rpc))).toMatchObject(classifyBroadcastError(rpc));
    const info = { code: 'INSUFFICIENT_FUNDS', shortMessage: 'insufficient funds', info: { error: { code: -32000, message: 'insufficient funds for gas' } } };
    expect(classifyBroadcastError(new EvmRpcError(info))).toMatchObject({ outcome: 'rejected', reason: 'insufficient_funds' });
  });
});

describe('anchoring on an rpcUrl whose node refuses the key: no output names it', () => {
  jest.setTimeout(60_000);
  let node: Awaited<ReturnType<typeof failingNode>>;
  let dir: string;
  const printed: string[] = [];

  beforeEach(async () => {
    node = await failingNode(503);
    dir = mkdtempSync(join(tmpdir(), 'tzun-test-rpc-redaction-'));
    printed.length = 0;
    for (const method of ['log', 'warn', 'error'] as const) {
      jest.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        printed.push(args.map((a) => everythingIn(a)).join(' '));
      });
    }
  });
  afterEach(async () => {
    jest.restoreAllMocks();
    await node.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('Tzun: anchorNow() and anchorNow({ force: true }) reject without it, and getAnchorState().lastError holds none', async () => {
    const events: string[] = [];
    const tzun = await Tzun.init({
      mode: 'dev',
      dbPath: join(dir, 'store.db'),
      logNamespace: 'test.redaction.example',
      anchoring: { publishers: { evm: { rpcUrl: node.rpcUrl, chain: SEPOLIA, privateKey: Wallet.createRandom().privateKey } }, autoStart: false },
      onLog: (event: string, fields: Record<string, unknown>) => events.push(everythingIn({ event, ...fields })),
    });
    try {
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { recommendation: 'approve' }, action: 'approved', reason: 'r' });
      const rejections: unknown[] = [];
      await tzun.anchorNow().catch((e: unknown) => rejections.push(e));
      await tzun.anchorNow({ force: true }).catch((e: unknown) => rejections.push(e));
      expect(rejections).toHaveLength(2);
      for (const e of rejections) {
        expect(everythingIn(e)).not.toContain(KEY);
        expect((e as Error).message).toContain('503');
      }
      const state = await tzun.getAnchorState();
      expect(state!.lastError).toContain('503');
      expect(everythingIn(state)).not.toContain(KEY);
    } finally {
      await tzun.close();
    }
    expect(events.join('\n')).not.toContain(KEY);
    expect(printed.join('\n')).not.toContain(KEY);
  });

  it("the scheduled loop's anchor_pass_failed event, logged or printed, names no URL", async () => {
    const tzun = await Tzun.init({ mode: 'dev', dbPath: join(dir, 'store.db'), logNamespace: 'test.redaction.example' });
    const logged: Array<{ event: string; fields: Record<string, unknown> }> = [];
    const scheduler = await createAnchorScheduler({
      storage: tzun.getStorage(),
      config: { publishers: { evm: { rpcUrl: node.rpcUrl, chain: SEPOLIA, privateKey: Wallet.createRandom().privateKey } } },
      expectation: {},
      tuning: { tickMs: 10 },
      onLog: (event: string, fields: Record<string, unknown>) => logged.push({ event, fields }),
    });
    try {
      await tzun.capture({ decider: { kind: 'human' as const, id: 'acct:u-test', agent: null, credential: null, freshness: null }, aiOutput: { recommendation: 'approve' }, action: 'approved', reason: 'r' });
      void scheduler.start();
      for (let i = 0; i < 300 && !logged.some((l) => l.event === 'anchor_pass_failed'); i++) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    } finally {
      await scheduler.close();
      await tzun.close();
    }
    const failed = logged.find((l) => l.event === 'anchor_pass_failed');
    expect(failed?.fields.error).toEqual(expect.stringContaining('503'));
    expect(everythingIn(logged)).not.toContain(KEY);
    expect(printed.join('\n')).not.toContain(KEY);
  });
});
