// Shared helpers for Helix's policies. Not a policy file itself
// (failproofai only loads files whose names end in `policies.mjs`).
import { customPolicies, allow, deny, instruct } from "failproofai";
import { mcpCall, history, userPrompts, askJev, compact } from "../../../../policykit/index.mjs";

export { allow, deny, instruct, userPrompts, compact };

/** Parsed results of earlier successful calls to `tool`, newest first. */
export function results(hist, tool) {
  return hist
    .filter((c) => c.tool === tool && c.result && typeof c.result === "object" && !c.result.error)
    .map((c) => c.result)
    .reverse();
}

/** Did an earlier call to `tool` whose args match `pred` succeed? */
export function did(hist, tool, pred = () => true) {
  return hist.some((c) => c.tool === tool && c.result && typeof c.result === "object" && !c.result.error && pred(c.args ?? {}, c.result));
}

export const lower = (v) => (typeof v === "string" ? v : JSON.stringify(v ?? "")).toLowerCase();
export const domainOf = (addr) => String(addr ?? "").trim().toLowerCase().split("@")[1] ?? "";

/**
 * Ask Jev narrow yes/no questions: `{id: [instructions, whenTrue, whenFalse]}`.
 * Returns `{id: probability}`, or null when Jev can't be reached so the caller
 * falls back to its code rule.
 */
export async function jev(state, questions) {
  const qs = {};
  for (const [id, [instructions, yes, no]] of Object.entries(questions)) {
    qs[id] = { type: "noul", instructions, criteria: { true: yes, false: no } };
  }
  // Jev occasionally answers 503 (jev_unavailable): retry once. Two 4 s attempts fit inside
  // failproofai's 10 s per-policy limit.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await askJev({ state, questions: qs, timeoutMs: 4000 });
    } catch {
      if (attempt === 0) await new Promise((r) => setTimeout(r, 300));
    }
  }
  return null;
}

/** The last `n` tool calls with their results, trimmed for Jev. */
export const recent = (hist, n = 10) => compact(hist.slice(-n).map((c) => ({ tool: c.tool, args: c.args, result: c.result })), 6000);

/**
 * Register a PreToolUse rule for this agent's MCP tools. `fn(call, ctx, hist)`
 * returns a decision (or nothing, meaning allow). A crash allows the call.
 */
export function rule(name, description, tools, fn) {
  customPolicies.add({
    name,
    description,
    match: { events: ["PreToolUse"] },
    fn: async (ctx) => {
      const call = mcpCall(ctx);
      if (!call || !tools.includes(call.tool)) return allow();
      try {
        return (await fn(call, ctx, history(ctx))) ?? allow();
      } catch {
        return allow();
      }
    },
  });
}
