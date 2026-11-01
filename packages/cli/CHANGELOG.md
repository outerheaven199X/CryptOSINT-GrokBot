# Changelog

## 0.3.1 (unreleased; not published to npm)

**Grok the Block: The Best Way To Lose All Your Money.** This is a local research preview. Not financial advice.

A fix release for four layout and labelling bugs found while recording the 0.3.0 launch video. No detector thresholds changed, no new dependencies, no redesign: v6 tokens, fonts and components only.

### Fixes
- **Pulse "Refreshed readings" at 1280 px.** The rows had no severity square, so the text fell into the 8 px square column and collapsed to one character per line. Each row now starts with its severity square (grey for a below-threshold reading) and the text uses the full column.
- **Compact disclaimer footer on short desktop viewports.** At 1280x720 the static footer took 180 px and left about 283 px for the panel. On viewports at least 768 px wide and at most 820 px tall, the label and links now share one row and the disclaimer spans the full width below them: the footer is about 124 px and the panel about 339 px. The notice keeps its full text, its 11 px size, its colour and all three links. Taller desktops and phones keep the 0.3.0 layout.
- **Case files report the real data status.** Exported case files said Data `real-cached` even right after a live refresh. The case file now carries `evidence.dataStatus`, a plain-language `dataStatusLabel`, the provider's `sourceAsOf` and the refresh run: `real-live-refreshed`, `real-stale-upstream`, `real-stale-carried`, `real-unavailable`, `real-stale-aged`, `real-cached-bundled`, `fixture-replay`, `synthetic-demo` or `imported-unverified`. "Live-refreshed" needs a fresh coverage row, a non-fixture refresh, a non-carried reading and an ingest time within the source's cadence, so stale upstream data is never marked fresh. `evidence.observed` (the observation kind) is unchanged for compatibility. The investigation rail shows the same status.
- **Pulse Real observations after a refresh.** Bundled stablecoin, Polymarket, Kalshi, options and MTG items were mixed in with the refreshed provider data as if current. After a refresh the list now has two labelled groups: rows from the refresh first (refreshed, FIXTURE, stale upstream or carried), then the bundled snapshot rows, each labelled "bundled snapshot (cached, not refreshed)" with the snapshot's ingest time. Nothing is deleted. The home "What's weird" strip uses the same order and labels. Before any refresh nothing changes.

### Tests
- `tests/ui/ui_031.py` (browser) and `tests/test_release_031.py` (static), plus new 0.3.1 checks in `tests/e2e/acceptance_pack.py` against the packed tarball (live refresh and FIXTURE second snapshot).

## 0.3.0 "Fresh Case Files" (unreleased; not published to npm)

**Grok the Block: The Best Way To Lose All Your Money.** This is a local research preview. Not financial advice.

### Evidence integrity
- The Observed section of every case file is now built deterministically from the detector's output: flagged, below threshold, unknown or stale. Model text can't add to it or override it.
- A Grok answer that contradicts the detector state is rejected whole, and the local evidence summary is shown with the reasons. That covers calling a quiet reading flagged or a flagged one quiet, inventing a severity, setting a state field, contradicting itself, or calling stale data live or up to date.
- Invented numbers, uncited claims and misattributed evidence are dropped item by item.
- All four contradiction cases from the November review are rejected. Adversarial tests cover false positives, fabricated severity, invented numbers, misattribution and contradictory responses. Control tests make sure negations, hypotheses and correct statements still pass.

### Refresh in `npx grok-the-block`
- A **Refresh** button in Pulse and the Watchlist. It runs only when you press it, in the launcher process, with no new dependencies.
- Keyless providers:
  - ECB SDMX reference rates, with the Frankfurter mirror as a fallback.
  - FRED fredgraph CSV: DEXUSEU (the H.10 fix), WTI, Brent and Henry Hub.
  - CFTC Socrata COT (`6dca-aqww`).
- The launcher ports the Python detectors with the same thresholds: daily move z ≥ 3 over 20 observations, the ECB vs H.10 cross-check (k = 5, ≥ 20 bp) and the COT shift (k = 3).
- Every reading keeps the provider's own date (`sourceAsOf`) and the fetch time (`ingestedAt`):
  - An upstream date older than its cadence is **upstream-stale**, never fresh.
  - A failed provider carries its last good reading as **stale**, with the error category.
  - Nothing unknown is shown as quiet.
- Network safety:
  - HTTPS only, to four allow-listed hosts. No redirects and an 8 MB cap per response.
  - Bounded retries on 429/5xx. HTML error pages count as failures.
  - One refresh at a time, behind a lock.
- What a refresh writes to the state directory: the current and previous snapshot, an append-only observation history and a refresh log.
- `GTB_REFRESH_FIXTURES` replays recorded responses for tests. Its output is labelled FIXTURE everywhere.
- Metals ETF proxies, Magic and CS2 stay on the bundled snapshot.

### Watchlists
- Watched items store the launcher's own reading. Each Refresh records:
  - whether the item changed, is unchanged, is stale or is unknown
  - the detector, value and threshold changes
  - the evidence ids, source and both dates
  - the checks that are still unknown
- A failed provider never overwrites the baseline.
- Notices are deduplicated and evidence-only, and they appear only in the app.

### Case files
- Snapshot provenance (bundled or refreshed, run id, fixture flag) and a `contentSha256` over everything except the generation time, so the same evidence gives the same file.

### UI fixes (v6 design unchanged)
- Card Explorer: the "cache synced" line no longer wraps at 320 px. The first card is visible at 320, 375 and 390 px.
- Investigate: "Ask again" no longer collapses when the consent or bounds panel re-renders.
- Watchlist: the refresh instructions no longer clip. They now point to the Refresh button.
- Pulse on phones: filters are collapsed behind "Filters · n active", so observations show on the first screen.
- Pulse labels each row refreshed, cached, carried after a failure or fixture.
- Universe shows "Typical observed spread" instead of the word arbitrage.

### Not changed
- No daemon, scheduler, telemetry, wallet or sign-in. Detector thresholds are unchanged.
- Connected Grok is still **UNVERIFIED** against the live xAI API. It is tested only against the local mock.
