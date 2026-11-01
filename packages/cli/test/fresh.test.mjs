// 0.3.0 Fresh Case Files: evidence integrity (detector state cannot be overridden by the model), the user-started keyless
// Refresh, and watchlist change detection across successive snapshots. Node built-ins only; never touches the network:
// providers are answered from REAL responses recorded on 2026-11-01 (test/fixtures/providers-20261101) or from stubs, and
// xAI is the local mock. Run: node --test packages/cli/test/fresh.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, cpSync, existsSync, statSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { start } from "../bin/grok-the-block.mjs";
import { validateAnswer, observedFromPacket, detectorState } from "../lib/investigate.mjs";
import { runRefresh, httpGet, fixtureFetch, parseEcbCsv, parseFredCsv, parseCot, parseFrankfurter, dailyMove, ALLOWED_HOSTS, PROVIDERS, mergeSnapshot, readBundled, SnapshotStore } from "../lib/refresh.mjs";
import { readingFor, diffReadings, applyRefreshToWatch } from "../lib/watch.mjs";
import { startMockXai } from "./mock-xai.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, "fixtures", "providers-20261101");
const UI = join(HERE, "..", "..", "..", "ui");                       // repo ui/ (holds the bundled data/everything.js)
const NOW = Math.floor(Date.parse("2026-11-01T11:30:00Z") / 1000);
const FAKE_KEY = "xai-TESTONLY" + "0123456789abcdefghijklmnopqrstuv";

/* ---------------- evidence integrity ---------------- */
const OID = "fx:EURAUD:CHECKS";
const QUIET = () => ({ schemaVersion: "gtb-evidence/v1", demo: false, instrument: { stableId: "fx:EURAUD", name: "EUR/AUD", assetClass: "fx", module: "fx" },
  sourceSnapshot: { kind: "real-cached", asOf: "2026-10-28", report: "everything-live-derived.json" },
  observations: [{ id: OID, detector: "FX_MOVE_VS_VOL", module: "fx", severity: "NONE", flagged: false, basis: "observed", what: "1-day move vs 20-day realised vol", metrics: { ratio: 0.42, threshold: 2.5 } }],
  coverage: [{ id: "cov:fx", module: "fx", status: "HEALTHY" }], sources: [{ id: "src:ecb", label: "ECB", url: "https://www.ecb.europa.eu/" }] });
const FLAGGED = () => ({ ...QUIET(), observations: [{ id: "energy:DHHNGSP:MOVE_VS_REALIZED_VOL", detector: "MOVE_VS_REALIZED_VOL", module: "energy", severity: "MEDIUM", detectorState: "flagged", basis: "observed", title: "Henry Hub fell 9.12% on 2026-10-27, 4.3× its 20-day realised volatility", trigger: { observed: 4.3, threshold: 3, unit: "× realised vol", window: "20 observations" } }],
  related: [{ observationId: "cot:Gold futures (COMEX):CHECKS", relation: "co-timed (within 24h)", confidence: "timing only", detector: "COT_POSITIONING_SHIFT", module: "cot", severity: "NONE", detectorState: "below-threshold" }] });
const UNKNOWN = () => ({ ...QUIET(), observations: [{ id: "mtg:Time Walk:CHECKS", detector: "GUIDE_MOVE_VS_30D_MEDIAN", module: "mtg", severity: "UNKNOWN", detectorState: "unknown", basis: "observed", title: "Time Walk: unknown, not quiet (insufficient snapshot history (day 4 of 14))" }] });
const STALE = () => ({ ...QUIET(), observations: [{ ...QUIET().observations[0], stale: true, dataQuality: ["stale upstream: the provider last published 2026-09-01"] }], coverage: [{ id: "cov:fx", module: "fx", status: "STALE", freshness: "carried-after-failure" }] });
const ans = (o) => JSON.stringify({ context: [], disprove: [{ text: "A later refresh in which the measure falls back under threshold." }], limits: [{ text: "test" }], ...o });

// The four contradiction cases from the November 2026 review (test-logs/contradiction-test.mjs), verbatim, plus its control.
const NOV_CASES = {
  flagged_no_numbers: { observed: [{ text: "The FX_MOVE_VS_VOL detector flagged EUR/AUD as an anomaly.", evidenceIds: [OID] }] },
  exceeded_with_packet_numbers: { observed: [{ text: "The ratio of 0.42 exceeded the 2.5 threshold, so the detector fired.", evidenceIds: [OID] }] },
  high_severity_claim: { observed: [{ text: "Severity is HIGH: the move is far above its normal volatility.", evidenceIds: [OID] }] },
  interpretation_claim: { observed: [{ text: "The detector measured a ratio of 0.42.", evidenceIds: [OID] }], interpretation: [{ text: "Because the detector flagged this move, a large participant was probably active." }] },
};
const CONTROL = { observed: [{ text: "The ratio was 0.42, below the 2.5 threshold; the detector did not flag it.", evidenceIds: [OID] }] };

test("November contradiction cases: all 4 rejected with a reason naming the detector state; control accepted", () => {
  for (const [k, c] of Object.entries(NOV_CASES)) {
    const v = validateAnswer(ans(c), QUIET(), []);
    assert.equal(v.ok, false, k + " must be rejected"); assert.equal(v.sections, null, k + ": nothing from the model is shown");
    assert.match(v.reason, /fail closed/); assert.match(v.reason, /below-threshold \(severity NONE, 0\.42 < 2\.5\)/, k);
    assert.ok(v.rejected.some(r => r.category === "state"), k);
  }
  const ok = validateAnswer(ans(CONTROL), QUIET(), []);
  assert.equal(ok.ok, true); assert.equal(ok.rejected.length, 0);
});
test("Observed is built from detector output only, never from model text", () => {
  const v = validateAnswer(ans({ observed: [{ text: "The ratio was 0.42, below the 2.5 threshold.", evidenceIds: [OID] }] }), QUIET(), []);
  assert.equal(v.sections.observed.length, 1); assert.equal(v.sections.observed[0].source, "detector"); assert.equal(v.sections.observed[0].detectorState, "below-threshold");
  assert.match(v.sections.observed[0].text, /below the detector threshold \(not flagged\)/); assert.ok(!v.sections.observed.some(o => /The ratio was/.test(o.text)));
  const none = validateAnswer(ans({}), FLAGGED(), []); assert.equal(none.ok, true);
  assert.deepEqual(none.sections.observed.map(o => o.detectorState), ["flagged", "flagged", "below-threshold"], "observation, its detector title, the related row");
  assert.match(none.sections.observed[0].text, /flagged by the detector \(severity MEDIUM\)\. Reading 4\.3 vs threshold 3/);
  assert.deepEqual(observedFromPacket(UNKNOWN()).map(o => o.detectorState), ["unknown", "unknown"]);
});
test("detector state: inconsistent detector fields fail closed to unknown", () => {
  assert.equal(detectorState({ severity: "HIGH", flagged: false }).state, "unknown");
  assert.equal(detectorState({ severity: "HIGH", trigger: { observed: 1.2, threshold: 3 } }).state, "unknown");
  assert.equal(detectorState({ severity: "NONE", detectorState: "flagged" }).state, "unknown");
  assert.equal(detectorState({ severity: "LOW", trigger: { observed: 3.4, threshold: 3 } }).state, "flagged");
  assert.equal(detectorState({ severity: "UNKNOWN" }).state, "unknown");
  assert.equal(detectorState({}).state, "unknown");
});
const REJECT = (name, packet, a, re) => test("adversarial: " + name, () => { const v = validateAnswer(ans(a), packet(), []); assert.equal(v.ok, false, JSON.stringify(v.rejected)); if (re) assert.match(v.reason, re); });
// false positives: asserting a flag the detector did not raise
REJECT("false positive on an unknown reading", UNKNOWN, { interpretation: [{ text: "The guide-price check triggered, which suggests a squeeze." }] }, /unknown/);
REJECT("'unusual' spike claimed on a quiet reading", QUIET, { interpretation: [{ text: "EUR/AUD saw an unusual spike." }] }, /below-threshold/);
REJECT("quiet claimed on a flagged reading", FLAGGED, { interpretation: [{ text: "Nothing unusual here; the reading is quiet." }] }, /flagged/);
REJECT("'did not fire' on a flagged reading", FLAGGED, { observed: [{ text: "The detector did not fire on Henry Hub.", evidenceIds: ["energy:DHHNGSP:MOVE_VS_REALIZED_VOL"] }] }, /flagged/);
REJECT("quiet claimed on an unknown reading", UNKNOWN, { interpretation: [{ text: "Time Walk is below its threshold, so it is all clear." }] }, /unknown, not quiet/);
// fabricated severity
REJECT("fabricated severity (CRITICAL vs MEDIUM)", FLAGGED, { interpretation: [{ text: "This is a CRITICAL observation." }] }, /fabricated severity: claims CRITICAL/);
REJECT("fabricated severity, lower case", FLAGGED, { interpretation: [{ text: "The severity is low, so it can be ignored." }] }, /fabricated severity: claims LOW/);
REJECT("fabricated high-severity phrase on a quiet reading", QUIET, { interpretation: [{ text: "A high-severity reading for EUR/AUD." }] }, /fabricated severity/);
// invented numbers
test("adversarial: invented numbers in observed and interpretation are rejected (item level)", () => {
  const v = validateAnswer(ans({ observed: [{ text: "EUR/AUD moved 3.7% on 2,400,000 volume.", evidenceIds: [OID] }], interpretation: [{ text: "Roughly 61.5% of that came from one desk." }] }), QUIET(), []);
  assert.equal(v.rejected.filter(r => /numbers that are not in the evidence/.test(r.reason)).length, 2);
  assert.ok(!JSON.stringify(v.sections || {}).includes("61.5"));
});
// misattributed evidence
REJECT("misattributed evidence: names one detector, cites another observation", FLAGGED, { observed: [{ text: "The COT_POSITIONING_SHIFT check is what moved here.", evidenceIds: ["energy:DHHNGSP:MOVE_VS_REALIZED_VOL"] }] }, /misattributed evidence/);
REJECT("misattributed evidence: observed cites only a source id", QUIET, { observed: [{ text: "The ECB page shows the move.", evidenceIds: ["src:ecb"] }] }, /misattributed evidence/);
REJECT("misattributed evidence: flag claimed about the related quiet row", FLAGGED, { observed: [{ text: "Gold positioning was flagged too.", evidenceIds: ["cot:Gold futures (COMEX):CHECKS"] }] }, /below-threshold/);
// contradictory responses
REJECT("contradictory response: one item says flagged, another says not flagged", QUIET, { observed: [{ text: "The detector did not flag EUR/AUD.", evidenceIds: [OID] }], interpretation: [{ text: "Since it was flagged, watch closely." }] }, /contradicts the detector/);
REJECT("model tries to set detector state at the top level", QUIET, { severity: "HIGH", observed: [{ text: "Measured.", evidenceIds: [OID] }] }, /tried to set detector state/);
REJECT("stale observation described as live", STALE, { interpretation: [{ text: "Live data shows EUR/AUD holding steady." }] }, /never live|stale/);
REJECT("stale observation described as up to date", STALE, { interpretation: [{ text: "This up-to-date reading confirms the trend." }] }, /stale/);
test("adversarial: two JSON objects, prose wrapper with conflicting objects, or no JSON fail closed", () => {
  assert.equal(validateAnswer(ans(CONTROL) + "\n" + ans(NOV_CASES.flagged_no_numbers), QUIET(), []).ok, false);
  assert.equal(validateAnswer("Sure! The detector flagged it.", QUIET(), []).ok, false);
});
test("not over-eager: negations, hypotheses and correct statements pass", () => {
  for (const t of ["If the ratio exceeded its threshold the detector would flag it; it did not.", "No anomaly was flagged on this snapshot.", "The detector has not flagged EUR/AUD.", "A move above the threshold in a later refresh would change this."]) {
    const v = validateAnswer(ans({ interpretation: [{ text: t }] }), QUIET(), []); assert.equal(v.ok, true, t + " -> " + JSON.stringify(v.rejected));
  }
  const f = validateAnswer(ans({ interpretation: [{ text: "The detector flagged this MEDIUM move; a scheduled storage report is one possible reason, not a measurement." }] }), FLAGGED(), []);
  assert.equal(f.ok, true, JSON.stringify(f.rejected));
});

/* ---------------- refresh ---------------- */
const fixDir = (mut) => { const d = mkdtempSync(join(tmpdir(), "gtb-fix-")); cpSync(FIX, d, { recursive: true }); if (mut) mut(d); return d; };
// Snapshot B for change detection: identical REAL recording except (1) the last EUR/TRY fix is moved +6% (a genuine,
// detectable change, labelled FIXTURE end to end), (2) CFTC is missing (simulated provider failure).
const snapB = () => fixDir(d => { const f = join(d, "ecb.csv"); const L = readFileSync(f, "utf8").trim().split("\n"); let i = L.length - 1; while (!L[i].includes(",TRY,")) i--; const c = L[i].split(","); c[3] = String(+(Number(c[3]) * 1.06).toFixed(4)); L[i] = c.join(","); writeFileSync(f, L.join("\n") + "\n"); rmSync(join(d, "cftc.json")); });

test("parsers read the recorded real provider responses", () => {
  const fx = parseEcbCsv(readFileSync(join(FIX, "ecb.csv"), "utf8")); assert.equal(Object.keys(fx).length, 16); assert.ok(fx.USD.length > 100);
  assert.ok(fx.USD.every((r, i, a) => !i || a[i - 1][0] < r[0]), "sorted by date");
  const w = parseFredCsv(readFileSync(join(FIX, "fred-DCOILWTICO.csv"), "utf8")); assert.ok(w.length > 200); assert.ok(w.every(r => Number.isFinite(r[1])), "'.' rows skipped");
  const cot = parseCot(JSON.parse(readFileSync(join(FIX, "cftc.json"), "utf8"))); assert.equal(Object.keys(cot).length, 8);
  assert.equal(parseEcbCsv("<html>error</html>"), null); assert.equal(parseFredCsv(""), null); assert.equal(parseCot({ error: true }), null);
  assert.equal(parseFrankfurter({ base: "USD", rates: {} }), null);
  const [s, p] = dailyMove("fx", "fx", "EUR/X", "EUR/X", [[1, 1], [2, 1]], "https://x"); assert.equal(s.length, 0); assert.equal(p[0].state, "unknown");
});
test("httpGet: only allow-listed hosts, no redirects, retries 429/5xx with backoff, HTML error pages and timeouts are failures", async () => {
  assert.deepEqual([...ALLOWED_HOSTS].sort(), ["api.frankfurter.dev", "data-api.ecb.europa.eu", "fred.stlouisfed.org", "publicreporting.cftc.gov"]);
  let n = 0; const spy = async () => { n++; return new Response("x"); };
  for (const u of ["https://evil.example/x", "http://fred.stlouisfed.org/x", "https://fred.stlouisfed.org:8443/x", "https://user@fred.stlouisfed.org/x", "file:///etc/passwd"]) assert.equal((await httpGet(u, { fetchImpl: spy })).error, u.startsWith("file") ? "host_not_allowed" : "host_not_allowed");
  assert.equal(n, 0, "never fetched");
  let k = 0; const flaky = async (u, o) => { k++; assert.equal(o.redirect, "error"); return k < 3 ? new Response("busy", { status: k === 1 ? 429 : 503 }) : new Response("a,b\n", { status: 200, headers: { "content-type": "text/csv" } }); };
  const waits = []; const r = await httpGet("https://fred.stlouisfed.org/graph/fredgraph.csv?id=X", { fetchImpl: flaky, wait: async (ms) => waits.push(ms) });
  assert.equal(r.ok, true); assert.equal(r.attempts, 3); assert.deepEqual(waits, [600, 1800]);
  const html = await httpGet("https://fred.stlouisfed.org/x", { fetchImpl: async () => new Response("<!doctype html><p>blocked</p>", { headers: { "content-type": "text/html" } }) }); assert.equal(html.error, "html_error_page");
  const slow = await httpGet("https://fred.stlouisfed.org/x", { timeoutMs: 30, attempts: 1, fetchImpl: (u, o) => new Promise((_, bad) => o.signal.addEventListener("abort", () => bad(new Error("aborted")))) }); assert.equal(slow.error, "timeout");
  const four = await httpGet("https://fred.stlouisfed.org/x", { fetchImpl: async () => new Response("no", { status: 404 }) }); assert.equal(four.error, "http_404"); assert.equal(four.attempts, 1, "4xx not retried");
});
test("refresh: recorded real responses -> fetched units with the providers' own dates; only allow-listed hosts contacted", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-")), hosts = new Set(); const f = fixtureFetch(FIX);
  const r = await runRefresh({ stateDir: st, root: UI, now: NOW, fixture: true, fetchImpl: async (u, o) => { hosts.add(new URL(u).hostname); return f(u, o); } });
  assert.equal(r.ok, true);
  const U = Object.fromEntries(r.units.map(u => [u.module, u]));
  for (const m of ["fx", "fx-h10", "energy", "cot"]) assert.equal(U[m].outcome, "fetched", m);
  assert.equal(U.fx.sourceAsOf, "2026-10-30"); assert.equal(U.fx.freshness, "fresh");
  for (const m of ["metals", "mtg", "cs2"]) { assert.equal(U[m].outcome, "not-refreshable"); assert.equal(U[m].freshness, "bundled-snapshot"); }
  for (const h of hosts) assert.ok(ALLOWED_HOSTS.has(h), h);
  const L = r.doc.live; const fxa = L.assets.filter(a => a.module === "fx");
  assert.equal(fxa.length, 16); assert.ok(fxa.every(a => a.ingestedAt === NOW && a.sourceAsOf && a.fixture === true));
  const mtg = L.assets.filter(a => a.module === "mtg"); assert.ok(mtg.length && mtg.every(a => a.ingestedAt !== NOW), "bundled modules keep their original ingest time: never look fresh");
  assert.ok(L.coverage.filter(c => ["fx", "energy", "cot"].includes(c.module)).every(c => c.via.startsWith("FIXTURE")), "fixture replays are labelled");
  const file = join(st, "snapshot", "live.json"); assert.ok(existsSync(file)); if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.ok(readFileSync(join(st, "snapshot", "history.jsonl"), "utf8").split("\n").filter(Boolean).length >= 28, "historical observations recorded (one per refreshed check)");
});
test("refresh: network off -> every refreshable unit fails, last good findings carried as STALE, unknown never becomes quiet", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-"));
  await runRefresh({ stateDir: st, root: UI, now: NOW, fetchImpl: fixtureFetch(FIX) });
  const before = new SnapshotStore(st).read().live;
  const r = await runRefresh({ stateDir: st, root: UI, now: NOW + 86400, http: { attempts: 1 }, fetchImpl: async () => { throw new Error("offline"); } });
  assert.equal(r.ok, true); const L = r.doc.live;
  for (const m of ["fx", "fx-h10", "energy", "cot"]) { const u = r.units.find(x => x.module === m); assert.equal(u.outcome, "failed-carried", m); }
  for (const m of ["fx", "energy", "cot"]) { const c = L.coverage.find(x => x.module === m); assert.equal(c.status, "STALE"); assert.equal(c.lastSuccessAt, NOW, "lastSuccessAt preserved"); assert.equal(c.lastAttemptAt, NOW + 86400); assert.equal(c.freshness, "carried-after-failure"); assert.equal(c.errorCategory, "network"); }
  assert.equal(L.probes.filter(p => p.module === "fx").length, before.probes.filter(p => p.module === "fx").length, "probes kept");
  assert.ok(L.probes.filter(p => p.module === "fx").every(p => p.carried && p.ingestedAt === NOW), "carried with their original ingest time");
  assert.equal(L.probes.filter(p => p.state === "unknown").length, before.probes.filter(p => p.state === "unknown").length);
});
test("refresh: an upstream date older than its cadence is upstream-stale, never fresh, even when downloaded today", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-"));
  const r = await runRefresh({ stateDir: st, root: UI, now: NOW + 40 * 86400, fetchImpl: fixtureFetch(FIX) });
  for (const m of ["fx", "energy", "cot", "fx-h10"]) { const u = r.units.find(x => x.module === m); assert.equal(u.outcome, "fetched"); assert.equal(u.freshness, "upstream-stale", m); }
  const c = r.doc.live.coverage.find(x => x.module === "fx"); assert.equal(c.status, "DEGRADED"); assert.equal(c.errorCategory, "upstream_stale");
});
test("refresh: lock held -> busy, nothing written; HTML error page from the ECB falls back to the Frankfurter mirror", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-")); const s = new SnapshotStore(st); const rel = s.lock(); assert.ok(rel);
  const r = await runRefresh({ stateDir: st, root: UI, now: NOW, fetchImpl: fixtureFetch(FIX) }); assert.equal(r.busy, true); rel();
  const fr = JSON.stringify({ base: "EUR", rates: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [new Date(Date.UTC(2026, 8, 1 + i)).toISOString().slice(0, 10), { USD: 1.1 + i / 1000, JPY: 160 + i / 10 }])) });
  const f = fixtureFetch(FIX);
  const r2 = await runRefresh({ stateDir: st, root: UI, now: NOW, only: ["fx"], fetchImpl: async (u, o) => u.includes("data-api.ecb") ? new Response("<html>maintenance</html>", { headers: { "content-type": "text/html" } }) : u.includes("frankfurter") ? new Response(fr, { headers: { "content-type": "application/json" } }) : f(u, o) });
  const u = r2.units.find(x => x.module === "fx"); assert.equal(u.outcome, "fetched"); assert.match(r2.doc.live.coverage.find(c => c.module === "fx").via, /Frankfurter/);
  assert.ok(r2.providers.some(p => p.provider === "ecb" && p.error === "html_error_page"));
});

/* ---------------- watchlists across two snapshots ---------------- */
test("watchlist: two successive snapshots -> genuine change, unchanged reading and failed provider are each reported from evidence", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-"));
  const A = await runRefresh({ stateDir: st, root: UI, now: NOW, fixture: true, fetchImpl: fixtureFetch(FIX) });
  const j = { items: ["fx:EUR/TRY", "fx:EUR/USD", "cot:Gold futures (COMEX)", "equities:SPY"].map(stableId => ({ stableId, reading: readingFor(A.doc.live, stableId) })), notices: [], notified: [] };
  assert.ok(j.items[0].reading.found && j.items[0].reading.checks.length);
  assert.equal(j.items[3].reading.found, false, "bundled-markets instrument: no refreshable reading");
  const B = await runRefresh({ stateDir: st, root: UI, now: NOW + 3600, fixture: true, fetchImpl: fixtureFetch(snapB()) });
  assert.equal(B.units.find(u => u.module === "cot").outcome, "failed-carried");
  const sum = applyRefreshToWatch(j, B.doc.live, { id: B.runId, at: B.at, fixture: true });
  const [tr, usd, gold, spy] = j.items.map(i => i.lastDiff);
  assert.equal(tr.state, "changed", tr.text); assert.ok(tr.changes.some(c => c.type === "MOVE_VS_REALIZED_VOL" && c.kind === "state" && /below-threshold/.test(c.from) && /^flagged /.test(c.to)), JSON.stringify(tr.changes));
  assert.ok(tr.evidenceIds.includes("fx:EUR/TRY:MOVE_VS_REALIZED_VOL")); assert.equal(tr.source, "FIXTURE (test replay, not live provider data): ECB SDMX (data-api.ecb.europa.eu)"); assert.equal(tr.sourceAsOf, "2026-10-30"); assert.match(tr.text, /FIXTURE replay/);
  assert.equal(usd.state, "unchanged", usd.text);
  assert.equal(gold.state, "unknown", gold.text); assert.match(gold.text, /provider failed/); assert.equal(j.items[2].reading.ingestedAt, NOW, "failed provider never overwrites the last good baseline");
  assert.equal(spy.state, "unknown");
  assert.equal(sum.changed, 1); assert.equal(sum.unchanged, 1); assert.equal(sum.unknown, 2);
  assert.equal(sum.notices.length, 1, "exactly one notice, for the genuine change"); assert.equal(sum.notices[0].stableId, "fx:EUR/TRY"); assert.equal(sum.notices[0].fixture, true);
  // the same snapshot again: the change is now the baseline -> unchanged, and the notice never repeats
  const again = applyRefreshToWatch(j, B.doc.live, { id: "again", at: B.at + 60, fixture: true });
  assert.equal(j.items[0].lastDiff.state, "unchanged"); assert.equal(again.notices.length, 0); assert.equal(j.notices.length, 1);
  // a muted item never notifies
  const m = { items: [{ stableId: "fx:EUR/TRY", muted: true, reading: readingFor(A.doc.live, "fx:EUR/TRY") }], notices: [] }; applyRefreshToWatch(m, B.doc.live, { id: "x", at: 1 }); assert.equal(m.notices.length, 0);
});
test("watch diff: an upstream-stale reading is 'stale', not 'unchanged'; a carried reading is 'unknown'", () => {
  const base = { found: true, checks: [{ type: "T", state: "below-threshold", severity: "NONE", ratio: 0.3 }], sourceAsOf: "2026-09-01" };
  assert.equal(diffReadings(base, { ...base, freshness: "upstream-stale" }).state, "stale");
  assert.equal(diffReadings(base, { ...base, freshness: "carried-after-failure" }).state, "unknown");
  assert.equal(diffReadings(base, { ...base, freshness: "fresh", checks: [{ type: "T", state: "below-threshold", severity: "NONE", ratio: 0.31 }] }).state, "changed");
});

/* ---------------- launcher API end to end ---------------- */
function call(port, method, path, { body, headers = {}, host = `127.0.0.1:${port}` } = {}) {
  return new Promise((ok, bad) => { const r = request({ host: "127.0.0.1", port, method, path, headers: { Host: host, Origin: `http://127.0.0.1:${port}`, "Content-Type": "application/json", "X-GTB-Request": "1", ...headers } }, res => { let b = ""; res.on("data", c => b += c); res.on("end", () => { let j = null; try { j = JSON.parse(b); } catch {} ok({ s: res.statusCode, h: res.headers, b, j }); }); }); r.on("error", bad); if (body !== undefined) r.write(JSON.stringify(body)); r.end(); });
}
async function launch({ env = {}, stateDir, refreshFetch } = {}) {
  const d = mkdtempSync(join(tmpdir(), "gtb-l-")); const root = join(d, "ui"); cpSync(UI, root, { recursive: true, filter: (s) => !/[\\/](legacy|cache|vendor|fonts)([\\/]|$)/.test(s.slice(UI.length)) });
  const app = start({ root, port: 0, open: false, log: () => {}, env, stateDir: stateDir || join(d, "state"), refreshFetch });
  await app.ready; const port = app.server.address().port; const ses = await call(port, "POST", "/api/session", { body: {} });
  return { port, ses, T: { "X-GTB-Token": ses.j.token }, stop: () => app.stop(), d };
}
test("API: /api/refresh is token-gated; /data/refreshed.js appears only after a refresh and only for the loopback Host", async () => {
  const L = await launch({ refreshFetch: fixtureFetch(FIX) });
  try {
    assert.equal(L.ses.j.refresh.mode, "user-started"); assert.equal(L.ses.j.refresh.snapshot, "bundled"); assert.equal(L.ses.j.refresh.providers.length, Object.keys(PROVIDERS).length); assert.ok(L.ses.j.refresh.providers.every(p => p.keyless));
    assert.equal((await call(L.port, "POST", "/api/refresh", { body: {} })).s, 403, "no token");
    assert.equal((await call(L.port, "POST", "/api/refresh", { body: {}, headers: { ...L.T, Origin: "https://evil.example" } })).s, 403);
    const stub = await call(L.port, "GET", "/data/refreshed.js"); assert.equal(stub.s, 200); assert.doesNotMatch(stub.b, /GTB_REFRESHED/);
    const r = await call(L.port, "POST", "/api/refresh", { body: {}, headers: L.T }); assert.equal(r.s, 200, r.b); assert.equal(r.j.status, "refreshed");
    const js = await call(L.port, "GET", "/data/refreshed.js"); assert.match(js.b, /^\/\* Grok The Block: snapshot from the last user-started Refresh/); assert.match(js.b, /window\.GTB_REFRESHED=/); assert.doesNotMatch(js.b, /<\/script/i);
    assert.equal((await call(L.port, "GET", "/data/refreshed.js", { host: "evil.example" })).s, 421);
    const s2 = await call(L.port, "POST", "/api/session", { body: {} }); assert.equal(s2.j.refresh.snapshot, "refreshed"); assert.equal(s2.j.refresh.last.runId, r.j.runId);
  } finally { await L.stop(); }
});
test("API: watchlist add records the launcher's own reading; refresh reports the change and one notice", async () => {
  const st = mkdtempSync(join(tmpdir(), "gtb-st-"));
  let L = await launch({ stateDir: st, env: { GTB_REFRESH_FIXTURES: FIX } });
  try {
    assert.equal(L.ses.j.refresh.fixtureMode, true);
    await call(L.port, "POST", "/api/refresh", { body: {}, headers: L.T });
    const add = await call(L.port, "POST", "/api/watchlist", { body: { op: "add", stableId: "fx:EUR/TRY", category: "ratesfx", last: { evidenceId: "fabricated", severity: "CRITICAL", kind: "real-cached" } }, headers: L.T });
    assert.equal(add.s, 200); const it = add.j.items[0]; assert.ok(it.reading.found); assert.ok(it.reading.checks.every(c => c.severity !== "CRITICAL"), "reading comes from the snapshot, not the client");
    assert.equal(it.current.found, true);
  } finally { await L.stop(); }
  L = await launch({ stateDir: st, env: { GTB_REFRESH_FIXTURES: snapB() } });
  try {
    const r = await call(L.port, "POST", "/api/refresh", { body: {}, headers: L.T });
    assert.equal(r.j.fixture, true); assert.equal(r.j.watch.changed, 1); assert.equal(r.j.watch.notices.length, 1);
    const w = await call(L.port, "POST", "/api/watchlist", { body: { op: "list" }, headers: L.T }); assert.equal(w.j.items[0].lastDiff.state, "changed"); assert.equal(w.j.notices.length, 1);
  } finally { await L.stop(); }
});
test("API: the mock's default answer no longer claims 'flagged' for a quiet packet, and a contradicting answer is rejected end to end", async () => {
  const m = startMockXai(); const mp = await m.ready;
  const L = await launch({ env: { XAI_API_KEY: FAKE_KEY, GTB_XAI_BASE_URL: `http://127.0.0.1:${mp}/v1` } });
  try {
    const r = await call(L.port, "POST", "/api/investigate", { body: { consent: true, packet: QUIET(), options: { timeoutMs: 5000 } }, headers: L.T });
    assert.equal(r.j.status, "answered", JSON.stringify(r.j.rejected)); assert.equal(r.j.sections.observed[0].detectorState, "below-threshold"); assert.equal(r.j.liveVerified, false); assert.equal(r.j.mock, true);
    m.setScenario("contradiction");
    const c = await call(L.port, "POST", "/api/investigate", { body: { consent: true, packet: QUIET(), options: { timeoutMs: 5000 } }, headers: L.T });
    assert.equal(c.j.status, "rejected"); assert.equal(c.j.sections, null); assert.match(c.j.reason, /fail closed/); assert.equal(c.j.observed[0].detectorState, "below-threshold");
  } finally { await L.stop(); await m.stop(); }
});
