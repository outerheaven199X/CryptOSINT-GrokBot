// Grok The Block // watchlist readings and change detection. Pure functions over a live snapshot (bundled or refreshed).
// A reading is what the detectors said about one instrument in one snapshot: each check is flagged / below-threshold /
// unknown, with the evidence id, the provider, the provider's own date and when this machine ingested it. A diff between two
// readings is "changed" only when a detector state, severity or measured value actually moved; a failed or carried provider
// is "unknown" (never "unchanged"); an upstream date past its cadence is "stale". Notices are derived from diffs only.
import { createHash } from "node:crypto";
import { unitOf, REFRESHABLE } from "./refresh.mjs";

const SEVR = (s) => ["NONE", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(s);
export function parseStableId(stableId, live) {
  const s = String(stableId || "");
  if (s.startsWith("mtg:")) { const pid = s.split(":")[2]; const a = (live.assets || []).find(x => x.printing && x.printing.id === pid); return { module: "mtg", asset: a ? a.id : null }; }
  const i = s.indexOf(":"); if (i < 1) return { module: null, asset: null };
  return { module: s.slice(0, i), asset: s.slice(i + 1) };
}
export function readingFor(live, stableId) {
  live = live || {}; const { module, asset } = parseStableId(stableId, live);
  const base = { stableId, module, asset, found: false, checks: [] };
  if (!module || !asset) return { ...base, reason: "unrecognised stable id" };
  const sigs = (live.signals || []).filter(x => x.module === module && (x.asset === asset || x.name === asset));
  const prbs = (live.probes || []).filter(x => x.module === module && x.asset === asset);
  const a = (live.assets || []).find(x => x.module === module && (x.id === asset || x.name === asset));
  if (!sigs.length && !prbs.length && !a) {
    if (!(live.coverage || []).some(c => c.module === module)) return { ...base, reason: "this instrument's source is not part of the refreshable snapshot (it comes from the bundled markets snapshot)", notRefreshable: true };
    return { ...base, reason: "not in the current snapshot" };
  }
  const unitsHere = new Set([...sigs, ...prbs].map(unitOf)); if (a) unitsHere.add(unitOf(a));
  const cov = (live.coverage || []).filter(c => unitsHere.has(c.module));
  const checks = [];
  for (const s of sigs) checks.push({ type: s.type, state: "flagged", severity: s.severity, observed: s.trigger ? s.trigger.observed : null, threshold: s.trigger ? s.trigger.threshold : null, unit: s.trigger ? s.trigger.unit || null : null, evidenceId: s.key, when: s.when, unitId: unitOf(s), carried: !!s.carried });
  for (const p of prbs) if (!sigs.some(s => s.type === p.type)) checks.push({ type: p.type, state: p.state === "unknown" ? "unknown" : "below-threshold", severity: p.state === "unknown" ? "UNKNOWN" : "NONE", ratio: p.ratio, reason: p.reason || null, evidenceId: module + ":" + asset + ":" + (sigs.length ? p.type : "CHECKS"), unitId: unitOf(p), carried: !!p.carried });
  checks.sort((x, y) => x.type < y.type ? -1 : x.type > y.type ? 1 : 0);
  const fr = cov.map(c => c.freshness || "bundled-snapshot");
  const ingested = [a && a.ingestedAt, ...sigs.map(s => s.ingestedAt), ...prbs.map(p => p.ingestedAt)].filter(v => v != null);
  return { ...base, found: true, name: (a && a.name) || (sigs[0] && sigs[0].name) || asset, checks,
    source: cov.map(c => c.via).filter(Boolean).join(" + ") || module, sourceAsOf: (a && (a.sourceAsOf || a.asOf)) || (cov[0] && cov[0].sourceAsOf) || null,
    ingestedAt: ingested.length ? Math.min(...ingested.map(v => typeof v === "number" ? v : Date.parse(v) / 1000)) : null,
    status: cov.map(c => c.status).join("/") || "UNKNOWN", freshness: fr.includes("carried-after-failure") || fr.includes("unavailable") ? "carried-after-failure" : fr.includes("upstream-stale") ? "upstream-stale" : fr.includes("bundled-snapshot") ? "bundled-snapshot" : fr.every(f => f === "fresh") && fr.length ? "fresh" : fr[0] || "unknown",
    errorCategory: cov.map(c => c.errorCategory).filter(Boolean)[0] || null, fixture: !!(a && a.fixture) || sigs.some(s => s.fixture) || prbs.some(p => p.fixture), refreshRun: (a && a.refreshRun) || (prbs[0] && prbs[0].refreshRun) || null };
}
const val = (c) => c.state === "flagged" ? c.observed : c.ratio;
const numEq = (a, b) => (a == null && b == null) || (a != null && b != null && Math.abs(Number(a) - Number(b)) < 1e-9);
export function diffReadings(prev, cur) {
  const unknownChecks = (cur.checks || []).filter(c => c.state === "unknown").map(c => ({ type: c.type, reason: c.reason || "unknown" }));
  const ctx = { source: cur.source || null, sourceAsOf: cur.sourceAsOf || null, ingestedAt: cur.ingestedAt || null, fixture: !!cur.fixture, unknownChecks, evidenceIds: (cur.checks || []).map(c => c.evidenceId) };
  if (!cur.found) return { state: "unknown", text: "Unknown, not quiet: " + (cur.reason || "no current reading") + ".", changes: [], ...ctx };
  if (cur.freshness === "carried-after-failure") return { state: "unknown", text: "Unknown, not unchanged: the provider failed in the last refresh (" + (cur.errorCategory || "error") + "). The last good reading is kept; nothing new was measured.", changes: [], ...ctx };
  if (!prev || !prev.found) return { state: "new", text: "Baseline recorded from " + (cur.source || cur.module) + (cur.sourceAsOf ? " (source as of " + cur.sourceAsOf + ")" : "") + ".", changes: [], ...ctx };
  const changes = [], P = new Map((prev.checks || []).map(c => [c.type, c])), C = new Map((cur.checks || []).map(c => [c.type, c]));
  for (const [t, c] of C) {
    const p = P.get(t);
    if (!p) { changes.push({ type: t, kind: "added", to: c.state, evidenceId: c.evidenceId }); continue; }
    if (p.state !== c.state || p.severity !== c.severity) changes.push({ type: t, kind: "state", from: p.state + (p.state === "flagged" ? " " + p.severity : ""), to: c.state + (c.state === "flagged" ? " " + c.severity : ""), fromEvidence: p.evidenceId, toEvidence: c.evidenceId, escalated: SEVR(c.severity) > SEVR(p.severity) });
    else if (!numEq(val(p), val(c))) changes.push({ type: t, kind: "reading", from: val(p), to: val(c), unit: c.state === "flagged" ? c.unit || "" : "× threshold", evidenceId: c.evidenceId });
  }
  for (const [t, p] of P) if (!C.has(t)) changes.push({ type: t, kind: "removed", from: p.state, evidenceId: p.evidenceId });
  const dated = prev.sourceAsOf && cur.sourceAsOf && prev.sourceAsOf !== cur.sourceAsOf ? { from: prev.sourceAsOf, to: cur.sourceAsOf } : null;
  const stale = cur.freshness === "upstream-stale";
  if (!changes.length) return { state: stale ? "stale" : "unchanged", text: (stale ? "Stale upstream: " : "Unchanged: ") + "same detector states and readings" + (dated ? " on a newer source date (" + dated.from + " → " + dated.to + ")" : " (source as of " + (cur.sourceAsOf || "unknown") + ")") + "." + (stale ? " The provider has not published within its usual cadence." : ""), changes, sourceDate: dated, ...ctx };
  const fmt = (c) => c.kind === "state" ? c.type + ": " + c.from + " → " + c.to : c.kind === "reading" ? c.type + ": " + c.from + " → " + c.to + " " + (c.unit || "") : c.type + " " + c.kind;
  return { state: "changed", text: "Changed: " + changes.map(fmt).join("; ") + (dated ? " (source " + dated.from + " → " + dated.to + ")" : "") + "." + (cur.fixture ? " FIXTURE replay (test data)." : ""), changes, sourceDate: dated, stale, ...ctx };
}
export const noticeKey = (stableId, d) => stableId + "|" + createHash("sha256").update(JSON.stringify([d.changes, d.sourceAsOf, d.evidenceIds])).digest("hex").slice(0, 16);
// Apply one refreshed snapshot to the stored watchlist (mutates j). Returns a summary of what moved.
export function applyRefreshToWatch(j, live, run) {
  const sum = { changed: 0, unchanged: 0, unknown: 0, stale: 0, new: 0, notices: [] };
  j.notices = Array.isArray(j.notices) ? j.notices : [];
  for (const it of j.items || []) {
    const cur = readingFor(live, it.stableId), d = diffReadings(it.reading || null, cur);
    const entry = { at: run.at, runId: run.id, fixture: !!run.fixture, ...d };
    it.lastDiff = entry; it.history = (Array.isArray(it.history) ? it.history : []).concat([{ at: run.at, runId: run.id, state: d.state, text: d.text, fixture: !!run.fixture }]).slice(-30);
    if (d.state !== "unknown") it.reading = cur;                         // a failed provider never overwrites the last good baseline
    sum[d.state] = (sum[d.state] || 0) + 1;
    if (d.state === "changed" && !it.muted) {
      const key = noticeKey(it.stableId, d);
      if (!j.notices.some(n => n.key === key) && !(j.notified || []).includes(key)) { const n = { key, at: run.at, runId: run.id, stableId: it.stableId, label: it.label || cur.name || it.stableId, text: d.text, evidenceIds: d.evidenceIds, source: d.source, sourceAsOf: d.sourceAsOf, fixture: !!run.fixture, seen: false }; j.notices.push(n); sum.notices.push(n); }
    }
  }
  j.notices = j.notices.slice(-200);
  return sum;
}
export { REFRESHABLE };
