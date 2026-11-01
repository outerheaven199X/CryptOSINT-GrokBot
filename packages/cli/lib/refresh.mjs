// Grok The Block // Refresh: an explicit, user-started keyless refresh for the npx launcher. Node built-ins only.
// - Runs ONLY when the user presses Refresh (POST /api/refresh). No daemon, no timer, no scheduler, no telemetry, no wallet.
// - Talks only to the provider host allow-list below (keyless, public, documented). No key is read or sent.
// - Ports the keyless modules of tools/build_everything.py (fx, fx-h10, energy, cot) with the SAME detector thresholds as
//   lib/grok_the_block/everything/detectors.py. Other modules (metals, mtg, cs2, prediction/equities/crypto "markets") are
//   carried from the bundled snapshot and labelled as such; they are not refreshed here.
// - Each unit is isolated: a failed provider keeps the last good findings (marked carried + STALE, lastSuccessAt preserved),
//   never turns unknown into quiet, and never makes old data look fresh. Source timestamps (sourceAsOf) are the provider's own
//   dates; ingestedAt is when this machine fetched it; an upstream date older than its publication cadence is "upstream-stale".
// - Writes only under the state directory: snapshot/live.json (current), live.prev.json, history.jsonl, refresh-log.jsonl.
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, openSync, closeSync, writeSync, unlinkSync, statSync, chmodSync, appendFileSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { randomBytes, createHash } from "node:crypto";

export const PROVIDERS = Object.freeze({
  ecb: { host: "data-api.ecb.europa.eu", label: "ECB SDMX (data-api.ecb.europa.eu)", fetches: "ECB euro reference exchange rates, 16 currencies, daily", rights: "free reuse with attribution: Source: ECB statistics", units: ["fx"] },
  frankfurter: { host: "api.frankfurter.dev", label: "Frankfurter v1 (ECB reference rates mirror)", fetches: "the same ECB reference rates, used only when the ECB host fails", rights: "ECB data, same attribution", units: ["fx"] },
  fred: { host: "fred.stlouisfed.org", label: "FRED fredgraph CSV (St. Louis Fed)", fetches: "public-domain US series: H.10 DEXUSEU (EUR/USD noon NY), EIA WTI, Brent and Henry Hub spot", rights: "public-domain US-government series only", units: ["fx-h10", "energy"] },
  cftc: { host: "publicreporting.cftc.gov", label: "CFTC Public Reporting (Socrata 6dca-aqww)", fetches: "Commitments of Traders, legacy futures-only, 8 markets, weekly", rights: "US-government public data", units: ["cot"] },
});
export const ALLOWED_HOSTS = Object.freeze(new Set(Object.values(PROVIDERS).map(p => p.host)));
export const REFRESHABLE = ["fx", "fx-h10", "energy", "cot"];
const CADENCE = { fx: 86400, "fx-h10": 86400, energy: 86400, cot: 86400, metals: 86400, mtg: 86400, cs2: 86400 };
// Upstream publication lag that is still "current" for each source (weekends, holidays, release schedules).
export const MAX_UPSTREAM_AGE_DAYS = { fx: 5, "fx-h10": 12, energy: 12, cot: 12 };
const UA = "grok-the-block/0.3.1 (local research preview; user-started refresh)";
const FX_CCYS = ["USD", "JPY", "GBP", "CHF", "CNY", "AUD", "CAD", "MXN", "TRY", "INR", "BRL", "ZAR", "SEK", "NOK", "KRW", "PLN"];
const ENERGY_FRED = { DCOILWTICO: "WTI crude oil spot (EIA via FRED)", DCOILBRENTEU: "Brent crude oil spot (EIA via FRED)", DHHNGSP: "Henry Hub natural gas spot (EIA via FRED)" };
const COT_MARKETS = { "GOLD - COMMODITY EXCHANGE INC.": "Gold futures (COMEX)", "SILVER - COMMODITY EXCHANGE INC.": "Silver futures (COMEX)", "WTI-PHYSICAL - NEW YORK MERCANTILE EXCHANGE": "WTI crude futures (NYMEX)",
  "WHEAT-SRW - CHICAGO BOARD OF TRADE": "SRW wheat futures (CBOT)", "CORN - CHICAGO BOARD OF TRADE": "Corn futures (CBOT)", "SOYBEANS - CHICAGO BOARD OF TRADE": "Soybean futures (CBOT)", "COFFEE C - ICE FUTURES U.S.": "Coffee C futures (ICE US)", "COCOA - ICE FUTURES U.S.": "Cocoa futures (ICE US)" };
const ECB_URL = "https://data.ecb.europa.eu/data/datasets/EXR";
const COT_URL = "https://publicreporting.cftc.gov/stories/s/r4w3-av2u";

/* ---------------- small statistics (mirror Python's statistics module) ---------------- */
const median = (xs) => { const a = [...xs].sort((x, y) => x - y), n = a.length; if (!n) return NaN; return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2; };
const pstdev = (xs) => { const m = xs.reduce((s, x) => s + x, 0) / xs.length; return Math.sqrt(xs.reduce((s, x) => s + (x - m) ** 2, 0) / xs.length); };
const rnd = (x, n) => { const f = 10 ** n; return Math.round(x * f) / f; };
const sgn = (x, d) => (x >= 0 ? "+" : "") + x.toFixed(d);
export const isoDate = (ts) => new Date(ts * 1000).toISOString().slice(0, 10);
const dayTs = (s) => Math.floor(Date.parse(String(s).slice(0, 10) + "T00:00:00Z") / 1000);
function robust(series, x, minN = 20) {
  if (series.length < minN) return [null, NaN, NaN];
  const med = median(series), mad = 1.4826 * median(series.map(v => Math.abs(v - med)));
  return [mad === 0 ? null : (x - med) / mad, med, mad];
}
const sevFor = (x, lo, mid, hi) => x >= hi ? "HIGH" : x >= mid ? "MEDIUM" : x >= lo ? "LOW" : "INFO";

/* ---------------- detectors (ported 1:1 from detectors.py; thresholds unchanged) ---------------- */
export function probe(asset, type, ratio, reason = null) { return { asset, type, state: ratio != null ? "measured" : "unknown", ratio: ratio == null ? null : rnd(ratio, 3), reason }; }
function sig({ source, category, asset, typ, severity, title, what, when, metrics, trigger, evidence, limits = [], basis = "observed", derivedOnly = false, name = null }) {
  return { key: `${source}:${asset}:${typ}`, source, category, asset, name: name || asset, type: typ, severity, basis, title, what, when: Math.trunc(when || 0), metrics, trigger, evidence: evidence.filter(e => e.url), limits: [...limits], derivedOnly, synthetic: false };
}
export function dailyMove(source, category, asset, name, rows, url, { window = 20, label = "daily", derivedOnly = false, extraLimits = [] } = {}) {
  rows = rows.filter(r => r[1] && r[1] > 0);
  if (rows.length < window + 2) return [[], [probe(asset, "MOVE_VS_REALIZED_VOL", null, `insufficient history (${rows.length} of ${window + 2} observations)`)]];
  const a = rows.slice(-window - 2, -2), b = rows.slice(-window - 1, -1);
  const rets = a.map((x, i) => Math.log(b[i][1] / x[1]));
  const r = Math.log(rows[rows.length - 1][1] / rows[rows.length - 2][1]);
  const rv = pstdev(rets);
  if (!rv) return [[], [probe(asset, "MOVE_VS_REALIZED_VOL", null, "zero realised volatility in window")]];
  const z = r / rv, last = rows[rows.length - 1], prev = rows[rows.length - 2];
  const out = [], prb = [probe(asset, "MOVE_VS_REALIZED_VOL", Math.abs(z) / 3)];
  const lim = [`Uses ${label} observations only; intraday timing is unknown.`, ...extraLimits];
  if (Math.abs(z) >= 3) out.push(sig({ source, category, asset, name, typ: "MOVE_VS_REALIZED_VOL", severity: sevFor(Math.abs(z), 3, 4, 5),
    title: `${name} ${r > 0 ? "rose" : "fell"} ${(Math.abs(Math.expm1(r)) * 100).toFixed(2)}% on ${isoDate(last[0])}, ${Math.abs(z).toFixed(1)}× its ${window}-day realised volatility`,
    what: `Log return ${sgn(r * 100, 2)}% vs a ${window}-day realised volatility of ${(rv * 100).toFixed(2)}% per observation.`, when: last[0],
    metrics: { returnPct: rnd(Math.expm1(r) * 100, 3), z: rnd(z, 2), realizedVolPct: rnd(rv * 100, 3), ...(derivedOnly ? {} : { last: last[1], prev: prev[1] }) },
    trigger: { observed: rnd(Math.abs(z), 2), threshold: 3, window: `${window} observations`, unit: "× realised vol" }, evidence: [{ label: `${name} source page`, url }], limits: lim, derivedOnly }));
  return [out, prb];
}
export function fxCrosscheck(asset, ecb, fred, urlA, urlB, { minBp = 20, k = 5 } = {}) {
  const fd = new Map(fred.map(r => [r[0], r[1]]));
  const pairs = ecb.filter(([t]) => fd.has(t) && fd.get(t) > 0).map(([t, a]) => [t, a, fd.get(t)]);
  if (pairs.length < 30) return [[], [probe(asset, "FIX_CROSSCHECK", null, `only ${pairs.length} matched dates between sources`)]];
  const bps = pairs.map(([, a, b]) => (b / a - 1) * 1e4);
  const [z, med] = robust(bps.slice(0, -1), bps[bps.length - 1]);
  const lastBp = bps[bps.length - 1], gap = Math.abs(lastBp - med);
  const prb = [probe(asset, "FIX_CROSSCHECK", z == null ? null : Math.abs(z) / k)];
  if (z != null && Math.abs(z) >= k && gap >= minBp) return [[sig({ source: "fx", category: "fx", asset, name: asset + " fix cross-check", typ: "FIX_CROSSCHECK", severity: "LOW",
    title: `ECB and Fed H.10 fixes for ${asset} disagree by ${sgn(lastBp, 0)} bp on ${isoDate(pairs[pairs.length - 1][0])} (usual gap ${sgn(med, 0)} bp)`,
    what: "Data-quality flag: the two official daily fixes diverged far more than usual. Check for a stale or revised value before reading anything into it.",
    when: pairs[pairs.length - 1][0], metrics: { gapBp: rnd(lastBp, 1), medianGapBp: rnd(med, 1), z: rnd(z, 2) },
    trigger: { observed: rnd(Math.abs(z), 2), threshold: k, window: `${bps.length - 1} matched dates`, unit: "robust z" },
    evidence: [{ label: "ECB reference rate", url: urlA }, { label: "Fed H.10 via FRED", url: urlB }], limits: ["Fixes are taken at different times of day, so some gap is expected."] })], prb];
  return [[], prb];
}
export function cotShift(market, name, rows, url, { k = 3 } = {}) {
  if (rows.length < 30) return [[], [probe(name, "COT_POSITIONING_SHIFT", null, `only ${rows.length} weekly reports`)]];
  const net = rows.filter(r => r.oi).map(r => (r.long - r.short) / r.oi * 100);
  const ch = net.slice(1).map((b, i) => b - net[i]);
  const [z] = robust(ch.slice(-53, -1), ch[ch.length - 1]);
  const prb = [probe(name, "COT_POSITIONING_SHIFT", z == null ? null : Math.abs(z) / k)];
  if (z != null && Math.abs(z) >= k) return [[sig({ source: "cot", category: "positioning", asset: name, name, typ: "COT_POSITIONING_SHIFT", severity: sevFor(Math.abs(z), k, 4, 5.5),
    title: `${name}: speculators' net position moved ${sgn(ch[ch.length - 1], 1)} pts of open interest in the week to ${isoDate(rows[rows.length - 1].ts)}`,
    what: `Non-commercial net position now ${sgn(net[net.length - 1], 1)}% of open interest; the weekly change is ${Math.abs(z).toFixed(1)} robust z vs 52 weeks.`,
    when: rows[rows.length - 1].ts, metrics: { netPctOI: rnd(net[net.length - 1], 2), weeklyChangePts: rnd(ch[ch.length - 1], 2), z: rnd(z, 2) },
    trigger: { observed: rnd(Math.abs(z), 2), threshold: k, window: "52 weekly reports", unit: "robust z" }, evidence: [{ label: "CFTC Commitments of Traders", url }],
    limits: ["Positions as of Tuesday, published Friday. Aggregate categories, no individual traders."] })], prb];
  return [[], prb];
}

/* ---------------- parsers (pure) ---------------- */
export function csvRows(txt) {
  const rows = []; let row = [], f = "", q = false;
  for (let i = 0; i < txt.length; i++) {
    const c = txt[i];
    if (q) { if (c === '"') { if (txt[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; continue; }
    if (c === '"') q = true; else if (c === ",") { row.push(f); f = ""; } else if (c === "\n" || c === "\r") { if (c === "\r" && txt[i + 1] === "\n") i++; row.push(f); rows.push(row); row = []; f = ""; } else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows.filter(r => r.length > 1 || r[0]);
}
export function parseEcbCsv(txt) {
  if (!txt || !String(txt).slice(0, 2000).includes("TIME_PERIOD")) return null;
  const rows = csvRows(String(txt)), h = rows[0], ci = h.indexOf("CURRENCY"), ti = h.indexOf("TIME_PERIOD"), vi = h.indexOf("OBS_VALUE");
  if (ci < 0 || ti < 0 || vi < 0) return null;
  const out = {};
  for (const r of rows.slice(1)) { const v = Number(r[vi]); if (!r[vi] || !Number.isFinite(v) || !/^\d{4}-\d{2}-\d{2}/.test(r[ti] || "")) continue; (out[r[ci] || "?"] ||= []).push([dayTs(r[ti]), v]); }
  for (const k of Object.keys(out)) out[k].sort((a, b) => a[0] - b[0]);
  return Object.keys(out).length ? out : null;
}
export function parseFrankfurter(j) {
  const rates = j && typeof j === "object" ? j.rates : null;
  if (!rates || typeof rates !== "object" || (j.base != null && j.base !== "EUR")) return null;
  const out = {};
  for (const d of Object.keys(rates).sort()) { const m = rates[d]; if (!m || typeof m !== "object") continue; for (const [c, v] of Object.entries(m)) if (typeof v === "number" && v > 0) (out[c] ||= []).push([dayTs(d), v]); }
  return Object.keys(out).length ? out : null;
}
export function parseFredCsv(txt) {
  if (!txt) return null; const lines = String(txt).split(/\r?\n/); if (!lines[0] || !lines[0].includes(",")) return null;
  const out = [];
  for (const r of csvRows(String(txt)).slice(1)) { if (r.length < 2 || !/^\d{4}-\d{2}-\d{2}/.test(r[0])) continue; const v = Number(r[1]); if (r[1] === "" || r[1] === "." || !Number.isFinite(v)) continue; out.push([dayTs(r[0]), v]); }
  return out.length ? out : null;
}
export function parseCot(rows) {
  if (!Array.isArray(rows)) return null; const out = {};
  for (const r of rows) { try { const x = { ts: dayTs(r.report_date_as_yyyy_mm_dd), long: Number(r.noncomm_positions_long_all), short: Number(r.noncomm_positions_short_all), oi: Number(r.open_interest_all) };
    if (!r.market_and_exchange_names || ![x.ts, x.long, x.short, x.oi].every(Number.isFinite)) continue; (out[r.market_and_exchange_names] ||= []).push(x); } catch {} }
  for (const k of Object.keys(out)) out[k].sort((a, b) => a.ts - b.ts);
  return Object.keys(out).length ? out : null;
}

/* ---------------- HTTP: allow-listed hosts, bounded, retried, never redirected ---------------- */
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
export async function httpGet(url, { fetchImpl = fetch, timeoutMs = 30000, attempts = 3, backoffMs = [600, 1800], maxBytes = 8 * 1024 * 1024, accept = "*/*", wait = sleep, signal } = {}) {
  let u; try { u = new URL(url); } catch { return { ok: false, error: "bad_url", attempts: 0 }; }
  if (u.protocol !== "https:" || !ALLOWED_HOSTS.has(u.hostname) || u.port || u.username) return { ok: false, error: "host_not_allowed", attempts: 0 };
  let last = { ok: false, error: "network", attempts: 0 };
  for (let i = 0; i < attempts; i++) {
    if (signal && signal.aborted) return { ok: false, error: "cancelled", attempts: i };
    const ac = new AbortController(), tm = setTimeout(() => ac.abort(), timeoutMs); const onAbort = () => ac.abort(); if (signal) signal.addEventListener("abort", onAbort, { once: true });
    try {
      const res = await fetchImpl(u.href, { method: "GET", headers: { "User-Agent": UA, Accept: accept }, redirect: "error", signal: ac.signal });
      if (res.status === 429 || res.status >= 500) last = { ok: false, status: res.status, error: res.status === 429 ? "rate_limited" : "http_5xx", attempts: i + 1 };
      else if (!res.ok) { clearTimeout(tm); return { ok: false, status: res.status, error: "http_" + res.status, attempts: i + 1 }; }
      else {
        const ct = String(res.headers.get("content-type") || "");
        const text = await res.text();
        clearTimeout(tm);
        if (Buffer.byteLength(text) > maxBytes) return { ok: false, error: "too_large", attempts: i + 1 };
        if (/text\/html/i.test(ct) || /^\s*<(!doctype|html)/i.test(text)) return { ok: false, status: res.status, error: "html_error_page", attempts: i + 1 };
        return { ok: true, status: res.status, text, attempts: i + 1 };
      }
    } catch (e) { last = { ok: false, error: ac.signal.aborted && !(signal && signal.aborted) ? "timeout" : signal && signal.aborted ? "cancelled" : "network", attempts: i + 1 }; }
    finally { clearTimeout(tm); if (signal) signal.removeEventListener("abort", onAbort); }
    if (i < attempts - 1) await wait(backoffMs[Math.min(i, backoffMs.length - 1)]);
  }
  return last;
}
// Test hook (GTB_REFRESH_FIXTURES=<absolute dir>): answer provider requests from local files instead of the network, so a
// second snapshot can be replayed deterministically. Every observation it produces is labelled "fixture" end to end.
export function fixtureFetch(dir) {
  const name = (u) => { const x = new URL(u); if (x.hostname === PROVIDERS.ecb.host) return "ecb.csv"; if (x.hostname === PROVIDERS.frankfurter.host) return "frankfurter.json"; if (x.hostname === PROVIDERS.fred.host) return "fred-" + x.searchParams.get("id") + ".csv"; if (x.hostname === PROVIDERS.cftc.host) return "cftc.json"; return null; };
  return async (u) => {
    const n = name(u); const p = n && join(dir, n);
    if (!p || !existsSync(p)) throw Object.assign(new Error("fixture missing (simulated network failure)"), { code: "ECONNREFUSED" });
    const body = readFileSync(p, "utf8");
    return new Response(body, { status: 200, headers: { "content-type": n.endsWith(".json") ? "application/json" : "text/csv" } });
  };
}

/* ---------------- units ---------------- */
const schemaFail = (r) => { r.error = "schema"; if (r.rec) { r.rec.ok = false; r.rec.error = "schema"; } };
const spark = (rows, n = 90) => rows.slice(-n).map(r => rnd(r[1], 6));
function startDate(now, days = 520) { return isoDate(now - days * 86400); }
async function unitFx(ctx) {
  const calls = [];
  const ecbUrl = `https://data-api.ecb.europa.eu/service/data/EXR/D.${FX_CCYS.join("+")}.EUR.SP00.A?startPeriod=${startDate(ctx.now)}&format=csvdata`;
  let r = await ctx.get("ecb", ecbUrl, "text/csv"); calls.push(r);
  let fx = r.ok ? parseEcbCsv(r.text) : null, via = "ECB SDMX (data-api.ecb.europa.eu)";
  if (r.ok && !fx) schemaFail(r);
  if (!fx) { const r2 = await ctx.get("frankfurter", `https://api.frankfurter.dev/v1/${startDate(ctx.now)}..?base=EUR&symbols=${FX_CCYS.join(",")}`, "application/json"); calls.push(r2); try { fx = r2.ok ? parseFrankfurter(JSON.parse(r2.text)) : null; } catch { fx = null; } if (r2.ok && !fx) schemaFail(r2); via = "Frankfurter v1 (ECB reference rates; ECB host failed this run)"; }
  if (!fx) return { ok: false, error: [...new Set(calls.map(c => c.error).filter(Boolean))].join(" / ") || "no_data", calls };
  ctx.fx = fx; const S = [], P = [], A = [];
  for (const c of Object.keys(fx).sort()) { const rows = fx[c]; const [s, p] = dailyMove("fx", "fx", `EUR/${c}`, `EUR/${c}`, rows, ECB_URL, { label: "daily ECB reference-rate" }); S.push(...s); P.push(...p);
    A.push({ id: `EUR/${c}`, universe: "fx-majors", name: `EUR/${c}`, last: rows[rows.length - 1][1], asOf: isoDate(rows[rows.length - 1][0]), spark: spark(rows), redistributable: true }); }
  const asof = Math.max(...Object.values(fx).map(r => r[r.length - 1][0]));
  return { ok: true, S, P, A, cov: [{ module: "fx", status: "HEALTHY", via, observed: Object.keys(fx).length, attribution: "Source: ECB statistics", sourceAsOf: isoDate(asof) }], calls, sourceAsOf: isoDate(asof) };
}
async function fred(ctx, id) { const r = await ctx.get("fred", `https://fred.stlouisfed.org/graph/fredgraph.csv?id=${id}`, "text/csv"); const rows = r.ok ? parseFredCsv(r.text) : null; if (r.ok && !rows) schemaFail(r); return { rows, call: r }; }
async function unitH10(ctx) {
  const usd = ctx.fx && ctx.fx.USD;
  if (!usd) return { ok: false, error: "needs_fresh_ecb_series", calls: [] };
  const { rows, call } = await fred(ctx, "DEXUSEU");
  if (!rows) return { ok: false, error: call.error || "no_data", calls: [call] };
  const [S, P] = fxCrosscheck("EUR/USD", usd, rows, ECB_URL, "https://fred.stlouisfed.org/series/DEXUSEU");
  return { ok: true, S, P, A: [], cov: [{ module: "fx-h10", status: "HEALTHY", via: "FRED fredgraph (H.10 DEXUSEU)", observed: 1, sourceAsOf: isoDate(rows[rows.length - 1][0]) }], calls: [call], sourceAsOf: isoDate(rows[rows.length - 1][0]), moduleOf: "fx" };
}
async function unitEnergy(ctx) {
  const S = [], P = [], A = [], calls = []; let ok = 0, asof = 0;
  for (const [sid, nm] of Object.entries(ENERGY_FRED)) {
    let { rows, call } = await fred(ctx, sid); calls.push(call);
    if (!rows) continue; ok++; rows = rows.slice(-400); asof = Math.max(asof, rows[rows.length - 1][0]);
    const [s, p] = dailyMove("energy", "energy", sid, nm, rows, `https://fred.stlouisfed.org/series/${sid}`, { label: "daily EIA spot" }); S.push(...s); P.push(...p);
    A.push({ id: sid, universe: sid === "DHHNGSP" ? "natgas" : "crude", name: nm, last: rows[rows.length - 1][1], asOf: isoDate(rows[rows.length - 1][0]), spark: spark(rows), redistributable: true });
  }
  if (!ok) return { ok: false, error: calls.map(c => c.error).filter(Boolean)[0] || "no_data", calls };
  return { ok: true, S, P, A, cov: [{ module: "energy", status: ok === 3 ? "HEALTHY" : "DEGRADED", via: "FRED fredgraph (EIA series)", observed: ok, attribution: "Source: U.S. Energy Information Administration", sourceAsOf: isoDate(asof) }], calls, sourceAsOf: isoDate(asof) };
}
async function unitCot(ctx) {
  const names = Object.keys(COT_MARKETS).map(n => "'" + n.replace(/'/g, "''") + "'").join(",");
  const q = new URLSearchParams({ $select: "market_and_exchange_names,report_date_as_yyyy_mm_dd,noncomm_positions_long_all,noncomm_positions_short_all,open_interest_all", $where: `market_and_exchange_names in(${names})`, $order: "report_date_as_yyyy_mm_dd DESC", $limit: String(80 * Object.keys(COT_MARKETS).length) });
  const r = await ctx.get("cftc", "https://publicreporting.cftc.gov/resource/6dca-aqww.json?" + q.toString().replace(/\+/g, "%20"), "application/json");
  let cot = null; try { cot = r.ok ? parseCot(JSON.parse(r.text)) : null; } catch { cot = null; } if (r.ok && !cot) schemaFail(r);
  if (!cot) return { ok: false, error: r.error || "no_data", calls: [r] };
  const S = [], P = [], A = [];
  for (const [m, nm] of Object.entries(COT_MARKETS)) { if (!cot[m]) continue; const [s, p] = cotShift(m, nm, cot[m], COT_URL); S.push(...s); P.push(...p);
    const net = cot[m].filter(x => x.oi).map(x => (x.long - x.short) / x.oi * 100);
    A.push({ id: nm, universe: /COFFEE|COCOA/.test(m) ? "softs" : /CHICAGO/.test(m) ? "grains" : "cot", name: nm, asOf: isoDate(cot[m][cot[m].length - 1].ts), spark: net.slice(-60).map(v => rnd(v, 2)), sparkLabel: "speculators' net % of OI", redistributable: true }); }
  const asof = Math.max(...Object.values(cot).map(v => v[v.length - 1].ts));
  return { ok: true, S, P, A, cov: [{ module: "cot", status: "HEALTHY", via: "CFTC Public Reporting (Socrata 6dca-aqww)", observed: Object.keys(cot).length, sourceAsOf: isoDate(asof) }], calls: [r], sourceAsOf: isoDate(asof) };
}
const UNITS = { fx: unitFx, "fx-h10": unitH10, energy: unitEnergy, cot: unitCot };

/* ---------------- merge: last-good carry, honest timestamps ---------------- */
// Which refresh unit an item of the live snapshot belongs to (fx-h10 items are module "fx", type FIX_CROSSCHECK, as in Python).
export function unitOf(x) { if (!x) return null; if (x.module === "fx" && x.type === "FIX_CROSSCHECK") return "fx-h10"; return x.module; }
export function upstreamFreshness(unit, sourceAsOf, now) {
  if (!sourceAsOf) return { freshness: "unknown-source-date", ageDays: null };
  const age = (now - dayTs(sourceAsOf)) / 86400; const max = MAX_UPSTREAM_AGE_DAYS[unit] ?? 3;
  return { freshness: age > max ? "upstream-stale" : "fresh", ageDays: Math.round(age * 10) / 10, maxAgeDays: max };
}
export function mergeSnapshot(prev, results, now, { fixture = false, runId, prevSource = "bundled" } = {}) {
  prev = prev || { signals: [], probes: [], coverage: [], assets: [], health: [] };
  const pIng = prev.generatedAt || null;
  const stamp = (x, ing) => ({ ...x, ingestedAt: x.ingestedAt ?? ing ?? pIng });
  const out = { kind: "everything", synthetic: false, generatedAt: now, signals: [], probes: [], coverage: [], assets: [], health: [], refreshedBy: "npx launcher (user-started Refresh)" };
  const healthPrev = Object.fromEntries((prev.health || []).map(h => [h.module, h]));
  const covUnit = (c) => c.module;
  const units = [];
  // units this launcher can refresh
  for (const u of REFRESHABLE) {
    const r = results[u]; const pc = (prev.coverage || []).filter(c => covUnit(c) === u); const hp = healthPrev[u] || healthPrev[u === "fx-h10" ? "fx" : u] || {};
    if (r && r.ok) {
      const fr = upstreamFreshness(u, r.sourceAsOf, now), mod = r.moduleOf || u;
      const tag = (x) => ({ ...x, module: mod, ingestedAt: now, sourceAsOf: x.asOf || r.sourceAsOf, refreshRun: runId, ...(fixture ? { fixture: true } : {}) });
      out.signals.push(...r.S.map(s => ({ ...tag(s), freshness: fr.freshness, ...(fr.freshness === "upstream-stale" ? { limits: [...s.limits, `Upstream source last published ${r.sourceAsOf}; older than its usual ${fr.maxAgeDays}-day publication lag.`] } : {}) })));
      out.probes.push(...r.P.map(tag)); out.assets.push(...r.A.map(tag));
      for (const c of r.cov) out.coverage.push({ ...c, ...(fixture ? { via: "FIXTURE (test replay, not live provider data): " + c.via } : {}), status: fr.freshness === "upstream-stale" ? "DEGRADED" : c.status, errorCategory: fr.freshness === "upstream-stale" ? "upstream_stale" : null, freshness: fr.freshness, upstreamAgeDays: fr.ageDays, lastAttemptAt: now, lastSuccessAt: now, ingestedAt: now, ...(fixture ? { fixture: true } : {}) });
      out.health.push({ module: u, cadenceS: CADENCE[u], status: fr.freshness === "upstream-stale" ? "DEGRADED" : r.cov[0].status, lastAttemptAt: now, lastSuccessAt: now, errorCategory: fr.freshness === "upstream-stale" ? "upstream_stale" : null, sourceAsOf: r.sourceAsOf, nextExpectedRun: null });
      units.push({ module: u, outcome: "fetched", freshness: fr.freshness, sourceAsOf: r.sourceAsOf, upstreamAgeDays: fr.ageDays, observed: r.cov[0].observed, signals: r.S.length, fixture });
    } else {
      const err = (r && r.error) || "not_attempted";
      const ps = (prev.signals || []).filter(x => unitOf(x) === u), pp = (prev.probes || []).filter(x => unitOf(x) === u), pa = (prev.assets || []).filter(x => unitOf(x) === u && u !== "fx-h10");
      const had = ps.length + pp.length + pa.length > 0;
      out.signals.push(...ps.map(s => ({ ...stamp(s), carried: true, freshness: "carried-after-failure", limits: [...(s.limits || []).filter(l => !/^Carried from the last good/.test(l)), `Carried from the last good fetch (ingested ${s.ingestedAt ? new Date((typeof s.ingestedAt === "number" ? s.ingestedAt : Date.parse(s.ingestedAt) / 1000) * 1000).toISOString() : "earlier"}); this refresh failed: ${err}.`] })));
      out.probes.push(...pp.map(p => ({ ...stamp(p), carried: true }))); out.assets.push(...pa.map(a => ({ ...stamp(a), carried: true })));
      for (const c of pc.length ? pc : [{ module: u, via: u, observed: 0 }]) out.coverage.push({ ...c, status: had ? "STALE" : "UNAVAILABLE", errorCategory: err, freshness: had ? "carried-after-failure" : "unavailable", lastAttemptAt: now, lastSuccessAt: c.lastSuccessAt ?? hp.lastSuccessAt ?? null, ingestedAt: c.ingestedAt ?? pIng });
      out.health.push({ ...hp, module: u, cadenceS: CADENCE[u], status: had ? "STALE" : "UNAVAILABLE", lastAttemptAt: now, errorCategory: err });
      units.push({ module: u, outcome: had ? "failed-carried" : "failed-unavailable", error: err, freshness: had ? "carried-after-failure" : "unavailable", sourceAsOf: (pc[0] || {}).sourceAsOf || null, lastSuccessAt: (pc[0] || {}).lastSuccessAt ?? hp.lastSuccessAt ?? null });
    }
  }
  // everything else is carried exactly as it was, labelled: this launcher does not refresh it
  const other = (x) => !REFRESHABLE.includes(unitOf(x));
  out.signals.push(...(prev.signals || []).filter(other).map(s => stamp(s))); out.probes.push(...(prev.probes || []).filter(other).map(p => stamp(p))); out.assets.push(...(prev.assets || []).filter(other).map(a => stamp(a)));
  for (const c of (prev.coverage || []).filter(c => !REFRESHABLE.includes(c.module))) { out.coverage.push({ ...c, freshness: c.freshness === "carried-after-failure" ? c.freshness : "bundled-snapshot", ingestedAt: c.ingestedAt ?? pIng, note: "Not refreshed by the npx launcher in 0.3.1; shown from the " + (prevSource === "bundled" ? "bundled package snapshot" : "previous snapshot") + "." });
    if (!units.some(x => x.module === c.module)) units.push({ module: c.module, outcome: "not-refreshable", freshness: "bundled-snapshot", sourceAsOf: c.sourceAsOf || null, lastSuccessAt: c.lastSuccessAt || null }); }
  for (const h of (prev.health || []).filter(h => !REFRESHABLE.includes(h.module))) out.health.push(h);
  const keys = out.signals.map(s => s.key); if (new Set(keys).size !== keys.length) throw new Error("duplicate observation ids after merge");
  return { live: out, units };
}

/* ---------------- state files (atomic, restrictive) ---------------- */
function atomicWrite(file, text) { const tmp = file + "." + randomBytes(6).toString("hex") + ".tmp"; writeFileSync(tmp, text, { mode: 0o600, flag: "wx" }); renameSync(tmp, file); try { chmodSync(file, 0o600); } catch {} }
export function readBundled(root) {
  try { const t = readFileSync(join(root, "data", "everything.js"), "utf8"); const a = t.indexOf("window.GTB_EVERYTHING="); const j = JSON.parse(t.slice(a + 22, t.lastIndexOf(";"))); return j; } catch { return null; }
}
export class SnapshotStore {
  constructor(stateDir) { this.dir = stateDir ? join(stateDir, "snapshot") : null; }
  get file() { return this.dir && join(this.dir, "live.json"); }
  read() { if (!this.dir || !existsSync(this.file)) return null; try { const j = JSON.parse(readFileSync(this.file, "utf8")); return j && j.schemaVersion === "gtb-refresh/v1" && j.live && j.live.kind === "everything" ? j : null; } catch { return null; } }
  write(doc) {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 }); try { chmodSync(this.dir, 0o700); } catch {}
    if (existsSync(this.file)) { try { atomicWrite(join(this.dir, "live.prev.json"), readFileSync(this.file, "utf8")); } catch {} }
    atomicWrite(this.file, JSON.stringify(doc) + "\n");
  }
  appendHistory(lines) {
    const f = join(this.dir, "history.jsonl"); appendFileSync(f, lines.map(l => JSON.stringify(l)).join("\n") + (lines.length ? "\n" : ""), { mode: 0o600 });
    try { if (statSync(f).size > 4 * 1024 * 1024) { const keep = readFileSync(f, "utf8").trim().split("\n").slice(-15000); atomicWrite(f, keep.join("\n") + "\n"); } } catch {}
  }
  appendLog(ev) { appendFileSync(join(this.dir, "refresh-log.jsonl"), JSON.stringify(ev) + "\n", { mode: 0o600 }); }
  history(filter) { const f = this.dir && join(this.dir, "history.jsonl"); if (!f || !existsSync(f)) return []; return readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(x => x && (!filter || filter(x))); }
  lock() {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 }); const p = join(this.dir, "refresh.lock");
    for (let i = 0; i < 2; i++) {
      try { const fd = openSync(p, "wx", 0o600); writeSync(fd, JSON.stringify({ pid: process.pid, at: Date.now() })); closeSync(fd); return () => { try { unlinkSync(p); } catch {} }; }
      catch (e) {
        if (e.code !== "EEXIST") throw e;
        let info = {}; try { info = JSON.parse(readFileSync(p, "utf8")); } catch {}
        let alive = false; try { if (info.pid) { process.kill(info.pid, 0); alive = true; } } catch { alive = false; }
        if (alive && Date.now() - (info.at || 0) < 15 * 60 * 1000) return null;
        try { unlinkSync(p); } catch {}
      }
    }
    return null;
  }
}
export function historyLines(live, runId, now) {
  const L = [];
  for (const s of live.signals || []) if (REFRESHABLE.includes(unitOf(s)) && s.refreshRun === runId) L.push({ run: runId, at: now, key: s.key, module: s.module, asset: s.asset, type: s.type, state: "flagged", severity: s.severity, observed: s.trigger ? s.trigger.observed : null, threshold: s.trigger ? s.trigger.threshold : null, when: s.when, sourceAsOf: s.sourceAsOf || null, fixture: !!s.fixture });
  for (const p of live.probes || []) if (REFRESHABLE.includes(unitOf(p)) && p.refreshRun === runId) L.push({ run: runId, at: now, key: `${p.module}:${p.asset}:${p.type}`, module: p.module, asset: p.asset, type: p.type, state: p.state === "unknown" ? "unknown" : p.ratio >= 1 ? "flagged" : "below-threshold", ratio: p.ratio, reason: p.reason || null, sourceAsOf: p.sourceAsOf || null, fixture: !!p.fixture });
  return L;
}

/* ---------------- one refresh run ---------------- */
export async function runRefresh({ stateDir, root, fetchImpl, now = Math.floor(Date.now() / 1000), fixture = false, only = null, http = {} } = {}) {
  if (!stateDir || !isAbsolute(stateDir)) return { ok: false, error: "no state directory: refresh needs somewhere private to keep the snapshot" };
  const store = new SnapshotStore(stateDir); const release = store.lock();
  if (!release) return { ok: false, busy: true, error: "a refresh is already running" };
  const runId = new Date(now * 1000).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z") + "-" + randomBytes(3).toString("hex");
  try {
    const cur = store.read(); const bundled = readBundled(root);
    const prev = cur ? cur.live : bundled ? bundled.live : null; const prevSource = cur ? "previous" : "bundled";
    const calls = [];
    const ctx = { now, get: async (provider, url, accept) => { const t0 = Date.now(); const r = await httpGet(url, { fetchImpl, accept, ...http }); const rec = { provider, host: new URL(url).hostname, ok: r.ok, status: r.status ?? null, error: r.ok ? null : r.error, attempts: r.attempts, ms: Date.now() - t0 }; calls.push(rec); r.rec = rec; return r; } };
    const results = {};
    for (const u of REFRESHABLE) {
      if (only && !only.includes(u)) continue;
      try { results[u] = await UNITS[u](ctx); } catch (e) { results[u] = { ok: false, error: "exception:" + String(e && e.name || "Error") }; }
    }
    const { live, units } = mergeSnapshot(prev, results, now, { fixture, runId, prevSource });
    live.lastRun = { id: runId, at: now, trigger: "user", fixture, ok: units.filter(u => REFRESHABLE.includes(u.module)).every(u => u.outcome === "fetched"), providers: calls, units };
    const doc = { schemaVersion: "gtb-refresh/v1", runId, at: now, fixture, live };
    store.write(doc); store.appendHistory(historyLines(live, runId, now)); store.appendLog({ run: runId, at: now, fixture, providers: calls, units: units.map(u => [u.module, u.outcome, u.freshness, u.error || null]) });
    return { ok: true, runId, at: now, fixture, units, providers: calls, doc };
  } finally { release(); }
}
export function refreshedScript(doc) {
  // A data-only script for /data/refreshed.js. JSON.stringify output is a JS literal; "<" is escaped so it can never close a tag.
  return "/* Grok The Block: snapshot from the last user-started Refresh (" + (doc.fixture ? "FIXTURE test replay" : "keyless providers") + "). Generated by the npx launcher. */\nwindow.GTB_REFRESHED=" + JSON.stringify({ runId: doc.runId, at: doc.at, fixture: !!doc.fixture, live: doc.live }).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029") + ";\n";
}
export function sha256(s) { return createHash("sha256").update(s).digest("hex"); }
