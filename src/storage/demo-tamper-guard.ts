/**
 * The arming guard that prevents demo-tamper hooks from firing against
 * production data.
 *
 * Two independent conditions must BOTH be satisfied:
 *   1. `TzunConfig.demoTamperHooks: true` — the caller explicitly opted in.
 *   2. The store is a known demo environment — either:
 *      (a) It is empty (fresh start) AND the adapter can demonstrate the store
 *          is loopback-local (see `DemoTamperTarget` below), OR
 *      (b) It already holds the sentinel row (previously armed), OR
 *      (c) `TZUN_DEMO_TAMPER_BOOTSTRAP=true` env var (one-shot migration valve
 *          for an already-populated demo store, and the only way to arm an
 *          empty store that is not demonstrably local; consumed on the arm
 *          that uses it — see `tryArmDemoTamperHooks`).
 *
 * If condition 2 fails, arming is refused for the process lifetime and a
 * structured error is logged. Every subsequent hook call throws
 * `DemoTamperGuardError`.
 *
 * BOTH outcomes are logged, arming as well as refusal: condition 2(a) — "the
 * store is empty" — is true of every production store on day one, and an
 * integrator copying `demoTamperHooks: true` out of a demo's config preset
 * would otherwise arm their real store permanently (the sentinel persists) with
 * nothing in the logs saying so.
 *
 * ── The locality check ─
 *
 * A log line makes the day-one arm *observable*, which is not the same as
 * *prevented*, and nothing reads that line at 3am on a production store. So the
 * empty-store path also needs the store to be local: `DemoTamperStoreView`
 * carries an optional `target()` capability, the adapters answer it, and the
 * guard checks the answer. Do not drop the check on the grounds that the view
 * has no connection information: `target()` is that information.
 *
 * The check is deliberately asymmetric: it opens the empty-store path only for
 * a target that is *demonstrably* loopback. An adapter that offers no `target`,
 * answers `{ kind: 'unknown' }`, throws, hands over a connection string that
 * does not parse, or names a host that would have to be resolved through DNS is
 * treated as REMOTE and refused. Every unknown fails closed, because the whole
 * failure mode being closed here is a production store that looked innocent.
 */

export class DemoTamperGuardError extends Error {
  constructor(message?: string) {
    super(message ?? 'demo tamper hooks are not enabled for this storage');
    this.name = 'DemoTamperGuardError';
  }
}

export const DEMO_SENTINEL_OWNER = 'tzun-sdk';

/**
 * Where the store an adapter is about to arm physically lives.
 *
 * `local`   — the data lives in this process and dies with it: the memory
 *             adapter, or an in-memory SQLite database. A file-backed SQLite
 *             store answers `unknown`, because a file is where a production
 *             store lives too.
 * `url`     — the adapter addresses its store over a connection string
 *             (Postgres). `classifyDemoTamperTarget` decides whether that
 *             string is demonstrably loopback.
 * `unknown` — the adapter knows it CANNOT answer (e.g. its connection
 *             parameters are ambiguous). Treated exactly like a remote target.
 *
 * `what` / `why` are logged on refusal, so they must never carry credentials.
 */
export type DemoTamperTarget =
  | { kind: 'local'; what: string }
  | { kind: 'url'; url: string }
  | { kind: 'unknown'; why: string };

/**
 * Minimal view of the storage adapter needed by the guard.
 * Each adapter implements this interface on the guard's behalf.
 */
export interface DemoTamperStoreView {
  /** Returns true iff the sentinel row exists. */
  hasSentinel(): Promise<boolean>;
  /** Write the sentinel row (idempotent — no-op if already present). */
  writeSentinel(): Promise<void>;
  /** Count of evidence envelopes currently stored. */
  envelopeCount(): Promise<number>;
  /**
   * OPTIONAL capability: say where this store lives, so the guard can refuse
   * the empty-store arm path against a remote one.
   *
   * Optional on purpose — an out-of-tree adapter that predates this method
   * keeps compiling. It does NOT keep the empty-store path: an adapter that
   * cannot answer is unsafe, not safe, and is refused. Do not "fix" a refusal
   * by defaulting a missing target to local.
   */
  target?(): DemoTamperTarget | Promise<DemoTamperTarget>;
}

/** Parse a dotted-quad IPv4 literal into 4 bytes, or null if it is not one. */
function parseIpv4(text: string): number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/**
 * Parse an IPv6 literal into 16 bytes, or null if it is not one.
 *
 * Handles `::` compression and a trailing IPv4 part (`::ffff:127.0.0.1`), which
 * is the shape that matters here: a v4-mapped address routes to the v4 address,
 * so `::ffff:127.0.0.1` is loopback and `::ffff:8.8.8.8` is not.
 */
function parseIpv6(text: string): number[] | null {
  if (!/^[0-9a-f:.]+$/i.test(text)) return null;
  const double = text.indexOf('::');
  if (double !== -1 && text.indexOf('::', double + 1) !== -1) return null;
  const headText = double === -1 ? text : text.slice(0, double);
  const tailText = double === -1 ? '' : text.slice(double + 2);
  const headTokens = headText === '' ? [] : headText.split(':');
  const tailTokens = tailText === '' ? [] : tailText.split(':');

  // A trailing IPv4 part, if present, is the last token overall.
  let v4: number[] | null = null;
  const last = tailTokens.length > 0 ? tailTokens : headTokens;
  if (last.length > 0 && last[last.length - 1].includes('.')) {
    v4 = parseIpv4(last[last.length - 1]);
    if (v4 === null) return null;
    last.pop();
  }

  const groupBytes = (tokens: string[]): number[] | null => {
    const bytes: number[] = [];
    for (const token of tokens) {
      if (!/^[0-9a-f]{1,4}$/i.test(token)) return null;
      const n = parseInt(token, 16);
      bytes.push((n >> 8) & 0xff, n & 0xff);
    }
    return bytes;
  };
  const head = groupBytes(headTokens);
  const tail = groupBytes(tailTokens);
  if (head === null || tail === null) return null;

  const fixed = head.length + tail.length + (v4 === null ? 0 : 4);
  if (fixed > 16) return null;
  if (double === -1 && fixed !== 16) return null;
  const middle = new Array<number>(16 - fixed).fill(0);
  return [...head, ...middle, ...tail, ...(v4 ?? [])];
}

/** True iff these address bytes are a loopback address. */
function bytesAreLoopback(bytes: number[]): boolean {
  if (bytes.length === 4) return bytes[0] === 127; // 127.0.0.0/8
  const firstTenZero = bytes.slice(0, 10).every((b) => b === 0);
  // ::ffff:a.b.c.d — IPv4-mapped, routes to the embedded IPv4 address.
  if (firstTenZero && bytes[10] === 0xff && bytes[11] === 0xff) return bytes[12] === 127;
  if (firstTenZero && bytes[10] === 0 && bytes[11] === 0) {
    if (bytes[12] === 127) return true; // ::a.b.c.d — deprecated v4-compatible
    return bytes[12] === 0 && bytes[13] === 0 && bytes[14] === 0 && bytes[15] === 1; // ::1
  }
  return false;
}

/**
 * Classify a bare host — an IP literal, a unix socket path, or a name.
 *
 * DNS is NOT consulted. A name that would have to be resolved is refused, for
 * two reasons: the resolver is not ours, and the answer can change between this
 * check and the connection. "I could not resolve it" and "I resolved it to
 * something remote" are the same answer here.
 */
function classifyHost(rawHost: string): { loopback: boolean; detail: string } {
  let host = rawHost.trim().toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const zone = host.indexOf('%');
  if (zone !== -1) host = host.slice(0, zone); // scope id: fe80::1%eth0
  if (host.startsWith('/')) {
    return { loopback: true, detail: `unix socket ${host}` };
  }
  if (host.endsWith('.')) host = host.slice(0, -1); // fully-qualified "localhost."
  if (host === 'localhost') return { loopback: true, detail: 'host localhost' };
  const bytes = host.includes(':') ? parseIpv6(host) : parseIpv4(host);
  if (bytes !== null) {
    return { loopback: bytesAreLoopback(bytes), detail: `host ${host}` };
  }
  return { loopback: false, detail: `host ${host} (name, not resolved)` };
}

/**
 * Classify a connection string. Never returns the string itself — connection
 * strings carry passwords and this value is logged.
 */
function classifyUrl(raw: string): { loopback: boolean; detail: string } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // libpq's keyword/value form ("host=... port=..."), a multi-host URL, a
    // zone-id literal: all unparseable here, all refused.
    return { loopback: false, detail: 'connection string does not parse as a URL' };
  }
  const hostParam = url.searchParams.get('host');
  if (url.hostname === '') {
    // `postgres:///db?host=/var/run/postgresql` is a unix socket; plain
    // `postgres:///db` takes its host from $PGHOST at connect time, which we
    // cannot see from here and which may well be remote.
    if (hostParam === null) {
      return { loopback: false, detail: 'no host in connection string (resolved from the environment)' };
    }
    return classifyHost(hostParam);
  }
  if (hostParam !== null && hostParam.toLowerCase() !== url.hostname.toLowerCase()) {
    return { loopback: false, detail: 'connection string names two different hosts' };
  }
  return classifyHost(url.hostname);
}

/**
 * Decide whether a target descriptor is demonstrably loopback-local.
 *
 * Everything that is not a positive demonstration is `loopback: false`.
 * `detail` is safe to log: it never contains credentials.
 */
export function classifyDemoTamperTarget(
  target: DemoTamperTarget | undefined,
): { loopback: boolean; detail: string } {
  if (target === undefined) {
    return { loopback: false, detail: 'adapter offers no target descriptor' };
  }
  switch (target.kind) {
    case 'local':
      return { loopback: true, detail: `local: ${target.what}` };
    case 'url':
      return classifyUrl(target.url);
    case 'unknown':
      return { loopback: false, detail: `unknown: ${target.why}` };
  }
}

/** Ask the adapter where it points. A throw is an answer: "I cannot say." */
async function describeTarget(store: DemoTamperStoreView): Promise<{ loopback: boolean; detail: string }> {
  try {
    return classifyDemoTamperTarget(await store.target?.());
  } catch {
    return { loopback: false, detail: 'adapter threw while describing its target' };
  }
}

/** Why the guard armed. Emitted on the `demo_tamper_guard_armed` log line. */
export type DemoTamperArmReason = 'sentinel' | 'empty-store' | 'bootstrap';

/** Why the guard refused. Emitted on the `demo_tamper_guard_refused` line. */
export type DemoTamperRefuseReason =
  | 'unsentineled-non-empty-store'
  | 'empty-store-not-loopback';

/**
 * Attempt to arm the demo tamper hooks for `store`.
 *
 * Returns `true` when armed (hooks are enabled) and `false` when refused
 * (hooks stay disabled). Both outcomes emit a structured line on stderr;
 * `backend` labels which adapter is arming so the line is actionable.
 *
 * The `TZUN_DEMO_TAMPER_BOOTSTRAP=true` env var is the one-shot migration valve
 * for an already-populated demo store, and it is CONSUMED here on the arm that
 * uses it, so the one-shot property does not rest on an operator remembering
 * to unset it: a lingering variable would arm any store the process was later
 * pointed at — a new database, or a restore from backup.
 *
 * It is consumed only on the bootstrap path. An arm that succeeded because the
 * store was empty AND demonstrably local, or was already sentinelled, did not
 * spend the valve, so clearing it there would silently disarm a migration the
 * operator had not performed yet. An empty store whose target is remote or
 * unknown DOES spend it: that arm could not have happened without it.
 *
 * The `empty` path additionally requires `store.target()` to demonstrate a
 * loopback destination. Refusing there is the point of the check,
 * so it is stated once, plainly: no target, an unparseable connection string,
 * a `{ kind: 'unknown' }` answer, a thrown answer, or a hostname that would
 * have to be resolved all mean REFUSE. The `sentinel` and `bootstrap` paths do
 * not consult the target.
 */
export async function tryArmDemoTamperHooks(
  store: DemoTamperStoreView,
  backend: string,
): Promise<boolean> {
  const armed = (reason: DemoTamperArmReason): true => {
    console.error(JSON.stringify({ type: 'demo_tamper_guard_armed', reason, backend }));
    return true;
  };

  if (await store.hasSentinel()) return armed('sentinel');

  const empty = (await store.envelopeCount()) === 0;
  const bootstrap = process.env.TZUN_DEMO_TAMPER_BOOTSTRAP === 'true';
  const target = await describeTarget(store);

  // The empty-store path is the one that fires on day one of a real
  // deployment, so it is the one that has to know where it is pointing.
  // `target.loopback` is a positive demonstration, never a default.
  if (empty && target.loopback) {
    await store.writeSentinel();
    return armed('empty-store');
  }

  if (bootstrap) {
    await store.writeSentinel();
    // Spend the one-shot valve, so the next store this process opens does not
    // inherit it. Two kinds of arm reach here: a populated store (the
    // migration case) and an empty store the adapter could not
    // demonstrate is local. Both are arms that could not have happened without
    // the valve, which is precisely when it is spent.
    delete process.env.TZUN_DEMO_TAMPER_BOOTSTRAP;
    return armed('bootstrap');
  }

  const refusal: Record<string, unknown> = empty
    // An empty store that is not demonstrably local is refused: every
    // production store is empty on day one.
    ? { type: 'demo_tamper_guard_refused', reason: 'empty-store-not-loopback', backend, target: target.detail }
    : { type: 'demo_tamper_guard_refused', reason: 'unsentineled-non-empty-store', backend };
  console.error(JSON.stringify(refusal));
  return false;
}

/**
 * Throw a `DemoTamperGuardError` unless the adapter is armed.
 * Every hook method calls this at entry; unarmed calls always throw.
 */
export function assertArmed(armed: boolean): void {
  if (!armed) {
    throw new DemoTamperGuardError();
  }
}
