/**
 * Minimal structured log surface for the Tzun SDK.
 *
 * One-line JSON to console.log by default; embedders may route via
 * `TzunConfig.onLog` to their own observability stack.
 *
 * Security rule: NEVER log PII or auth material.
 * Excluded fields (the Python SDK excludes the same):
 *   - API keys, tokens, bearer credentials
 *   - action, reason, step reasons and aiOutput content (user / model payload)
 *   - decider and step actor identifiers, decider commitment openings
 *   - link attrs
 *   - a mandate's principal (`principal.signer`, `statement.signer`)
 *   - annotatedBy values on non-registration paths
 */
export type LogSink = (event: string, fields: Record<string, unknown>) => void;

/**
 * Emit a structured log event.
 *
 * If `sink` is provided (from `TzunConfig.onLog`), the event is delegated to
 * the caller-supplied sink. Otherwise it is serialised as a single-line JSON
 * object to `console.log`.
 */
export function sdkLog(
  sink: LogSink | undefined,
  event: string,
  fields: Record<string, unknown>,
): void {
  if (sink) {
    sink(event, fields);
    return;
  }
  console.log(JSON.stringify({ event, ...fields }));
}
