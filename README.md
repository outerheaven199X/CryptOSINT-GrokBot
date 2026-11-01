# Grok The Block

**Grok the Block: The Best Way To Lose All Your Money**

Unusual-activity analysis across selected public markets, with the evidence behind every flag.

> **Experimental, user-run market-forensics research tool; rule-based observations with linked evidence and explicit coverage limits. No measured predictive accuracy.**

> **Research preview.** Bundled data is a cached snapshot plus labelled synthetic examples. Fresh data arrives only when you press **Refresh** (keyless public providers for FX, energy and CFTC positioning); there is no background feed, and it has not been tested on physical devices. Hosted alerts are **NO GO**. The evaluation is **unlabeled** (the human-review gate is blocked), so **no detection accuracy has been measured or is claimed.** Not financial advice. See the [Legal notice](#legal-notice).

## Quick start (npm, no clone)
```bash
npx grok-the-block              # Node >= 22.14.0; opens http://127.0.0.1:<port>/ in your browser
npx grok-the-block --no-open    # print the URL only
```
1. **Pulse** lists real observations from the bundled snapshot.
2. Press **Refresh** to fetch today's public data from keyless providers. Nothing is fetched until you press it.
3. **Investigate** any observation for an evidence-only case file, then export it as HTML or JSON. Each file carries a content checksum, so the same evidence gives the same file.
4. **Watch** it. The next Refresh tells you what changed, when, which source it came from and which checks are still unknown.

The launcher serves only `127.0.0.1`. It has no runtime dependencies, install hooks, wallet, sign-in, telemetry or background daemon. Ctrl+C stops it. Details are in [packages/cli/README.md](packages/cli/README.md).

### Bundled, optional and limited
| | What you get |
|---|---|
| **Bundled (works offline)** | The v6 UI, a cached snapshot of real public data (FX, energy, CFTC, metals ETF proxies, Magic and CS2 prices) with its own as-of dates, labelled synthetic examples, Investigations with offline case files, Pulse and a local watchlist |
| **Refresh (user-started, keyless)** | FX: the ECB reference rates (with the Frankfurter mirror if the ECB host fails) and the Fed H.10 USD/EUR fix from FRED. Energy: WTI, Brent and Henry Hub spot from FRED. Futures positioning: CFTC Commitments of Traders. The same detectors and thresholds as the Python skills run in the launcher |
| **Stays on the snapshot** | Metals ETF proxies, Magic and CS2 prices and the wider markets family. Their keyless sources need the Python skills from a clone (`tools/build_everything.py --fetch`), or they are undocumented endpoints we don't call from the package |
| **Optional Connected Grok** | Bring your own `XAI_API_KEY`. Every question shows the exact evidence packet first and asks for consent, and xAI bills your account. **The live xAI path is UNVERIFIED**: it is tested only against a local mock |
| **Provider limits** | The ECB and FRED publish on business days and FRED's energy series lag by about a week. CFTC is weekly (Tuesday positions, published Friday). An upstream date older than its cadence is shown as **upstream-stale**, never fresh. A failed provider keeps its last good reading, marked **stale** with the error. It never becomes quiet. Provider display rights are unverified (see [docs/PROVIDER-RIGHTS.md](docs/PROVIDER-RIGHTS.md)) |

## What it is
Grok The Block is the everything app for unusual market activity. Together with Grok Bot, it flags unusual activity across prediction markets, US stocks and options, Treasuries, macro and calendar events, and crypto, and it shows the evidence behind every flag. It never tells you to buy, sell or hold.

Its Python skills run locally or through Grok Bot and write JSON reports. The `ui/` dashboard (design v6) shows those reports with their evidence and states what the data can't show. It never trades, never connects a wallet, never says who traded and never claims wrongdoing.

## Markets covered
All markets below run through one cross-market engine (`skills/signals`, `lib/grok_the_block/markets/`) and appear together in the **Signals** view.

| Market | What is flagged | Public sources |
|---|---|---|
| Prediction markets | Polymarket odds jumps, volume spikes and large trades from new wallets; Kalshi price and volume shocks | Polymarket Gamma/CLOB, Kalshi public API |
| US stocks and options | Daily price/volume anomalies; unusual options volume and open interest | Yahoo/Nasdaq, Cboe delayed |
| Bonds | Treasury yield-curve moves | Treasury.gov / FRED |
| Macro and calendar | Macro series anomalies; activity linked to Fed decisions, BLS releases, Treasury auctions and options expiry (`data/event-calendar.json`) | Yahoo, federalreserve.gov, bls.gov, fiscaldata.treasury.gov |
| Filings | SEC Form 4 and 8-K events as context (opt-in) | SEC EDGAR |
| Crypto | Perp open-interest and funding shocks; stablecoin supply changes; daily anomalies | OKX/Coinbase, DefiLlama |
| FX | ECB reference-rate moves vs realised volatility (16 EUR crosses); ECB vs Fed H.10 fix cross-check (data quality) | ECB statistics (via Frankfurter when the ECB host is unreachable), FRED H.10 |
| Metals | Gold, silver, platinum and palladium through ETF proxies (GLD, IAU, SLV, PPLT, PALL): moves, volume, GLD-vs-IAU tracker divergence. Derived signals only, not spot | Nasdaq quote history |
| Energy | WTI, Brent and Henry Hub spot moves | EIA via FRED |
| Futures positioning | Weekly speculator positioning shifts in gold, silver, crude, grains, coffee, cocoa | CFTC Commitments of Traders |
| Collectibles | Magic cards: US-vs-EU venue spread after FX, guide moves once 14 days of our own snapshots exist. Thin-market detectors (sparse-sale gate, per-grade outlier sales, grade-mix shift, round-trip patterns, supply shocks, guide-vs-sales lag) are built and shown on labelled synthetic examples. CS2 skins: ask-vs-sale gap, derived only and on the roadmap | Scryfall, Steam Community Market (undocumented endpoint) |
| Solana module | Token, wallet, rug-replay, copy-trade and leaderboard scans, plus X promo-account and media checks | Solana RPC, DexScreener, RugCheck, Helius (optional) |

Signals from different markets are linked when they line up (convergence, same-family repricing, divergence), and each link says how certain it is.

## Everything it tracks
**Commodities**
- **Precious metals:** gold (GLD, IAU), silver (SLV), platinum (PPLT) and palladium (PALL), through ETF proxies
- **Energy:** WTI crude, Brent crude and Henry Hub natural gas (EIA spot via FRED)
- **Futures positioning (CFTC COT):** gold and silver (COMEX), WTI crude (NYMEX), SRW wheat, corn and soybeans (CBOT), coffee C and cocoa (ICE US)
- **Commodity ETFs in the equities set:** GLD, SLV, USO, XLE

**Rates and FX**
- **FX:** 16 currencies against the euro (USD, JPY, GBP, CHF, CNY, AUD, CAD, MXN, TRY, INR, BRL, ZAR, SEK, NOK, KRW, PLN) from ECB reference rates, cross-checked against the Fed H.10 fix for USD, JPY and GBP
- **Treasuries:** 3-month, 2-year, 5-year, 10-year and 30-year yields
- **Rates and dollar ETFs:** TLT, IEF, SHY, HYG, UUP

**Stocks and options**
- **Index and sector ETFs:** SPY, QQQ, IWM, XLF, SMH, XLE
- **Options:** unusual volume and open interest (Cboe delayed)
- **Filings:** SEC Form 4 and 8-K (opt-in)

**Prediction markets**
- Polymarket and Kalshi (all non-sports categories)

**Crypto**
- Perp open interest and funding, stablecoin supply, daily anomalies and the Solana token and wallet module

**Collectibles**
- **Magic: The Gathering (24 cards, pinned to paper printings):** Black Lotus, Mox Sapphire, Ancestral Recall, Time Walk, Timetwister, Underground Sea, Volcanic Island, Gaea's Cradle, The One Ring, Sheoldred the Apocalypse, Ragavan Nimble Pilferer, Orcish Bowmasters, Mana Crypt, Jeweled Lotus, Force of Will, Wrenn and Six, Mox Diamond, Cyclonic Rift, Rhystic Study, Dockside Extortionist, Smothering Tithe, Fierce Guardianship, Imperial Seal, Grim Monolith
- **Counter-Strike 2 skins and cases (experimental):** AK-47 Redline, AWP Asiimov, AK-47 Vulcan, M4A4 Howl, Desert Eagle Blaze, USP-S Kill Confirmed, Operation Breakout Weapon Case, Kilowatt Case, Revolution Case, Natus Vincere Paris 2023 sticker
- **Coming next:** Pokémon cards, retro game cartridges and other card games use the same adapter and switch on once their data and image rights are cleared

The full directory of 53 asset classes is in **All Markets** inside the app.

## What it does
**Views** (`ui/`, top navigation):

| View | Shows |
|---|---|
| Home | Search box, "Try" examples, and Grok Bot |
| Pulse | Real observations from the current snapshot, with Refresh (launcher only), filters, provenance labels (refreshed, cached, carried after a failure, fixture) and investigation shortcuts |
| Investigate | An evidence-only case file for one observation. The detector's own state (flagged, below threshold, unknown or stale) is fixed and Grok can't override it. Export it as HTML or JSON, or use optional Connected Grok |
| Watchlist | Watched observations, what changed at the last Refresh, which source and when, which checks are still unknown, and evidence-only notices |
| Universe | Every asset class (53 so far) as a tile grid with category and status filters. Each tile opens venues, the typical observed spread, the best data source and its licence status, plus the live evidence for that class |
| Anomalies | One feed across every market. Live cached data and synthetic examples sit in separate columns, with "closest to threshold" and "unknown, not quiet" lists. Evidence opens on the result stage |
| Token | Kinetic result sequence: hazard wipe, RESULT, five stats counting up, then the verdict roll. Details tabs: Holders, Timeline, Why flagged |
| Wallet | The same result sequence for a wallet. Rows are the tokens it touched |
| Replay | A token's timeline with a scrubber and an optional X-post overlay |
| Signals | Summary, source filters, expandable evidence dossiers, related observations, coverage matrix, calendar, watch telemetry |
| Threats | Alert feed with a severity filter, expandable alerts, and a monitoring snapshot |
| Shill net | Graph of linked X accounts (anonymized): clusters, isolated accounts, evidence panel |
| Copy net | Leader → follower copy-trade graph from a token scan, with an empty state when there are no links |
| Leaderboard | Sortable ranking of repeat launch-pattern wallets seen on this machine |
| Provenance | Media checks: hashes, C2PA, reuse, metadata signals |

- **Grok Bot:** a three.js character on the result stage. It drops in, hovers, blinks, follows the cursor and reacts to verdicts, and its TL;DR box types out a summary of the report.
- **Verdict phrases** are mapped from each report's severity and score, for example CRITICAL → "Red flags stacking up" and LOW with a high organic score → "Looks organic". An unknown severity reads "Mixed signals", never clean. The phrases never advise buying, selling or holding.
- **Ask about this:** on report headers, holder rows, Why-flagged findings, Live feed items, Signals items and dossiers, Threats alerts, Shill/Copy net evidence panels, Leaderboard rows and Provenance records. It copies a structured prompt (view, item, evidence ID, report and timestamp, key facts, question) built only from page data. You paste it into Grok Bot yourself. If the clipboard isn't available, a selectable text box opens instead.
- **Live feed and ticker:** these replay items from the loaded reports.
- **Open / Export:** Open loads report JSON files from your device. Export saves the current report as JSON.

## Quick start from a clone
```bash
git clone https://github.com/outerheaven199X/groktheblock && cd groktheblock
python3 -m http.server 8000        # Windows: py -m http.server 8000
# open http://localhost:8000/ui/
```
- **Serve over http.** From `file://` the browser blocks the 3D modules, and the app falls back to a static bot.
- **Add `?nowebgl`** to force that fallback.

**Run the skills** (standalone; they fetch public data when run):
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python skills/token-scan/scripts/token_scan.py <mint>
.venv/bin/python skills/wallet-scan/scripts/wallet_scan.py <wallet>
.venv/bin/python skills/rug-replay/scripts/rug_replay.py <mint>
.venv/bin/python skills/signals/scripts/signals.py scan
```
Reports go to `out/`. Load them in the UI with **Open**. With Grok Bot, ask it to install the skills from this repo; each `skills/*/SKILL.md` tells it what to run.

**Tests:**
```bash
python3 tests/run_all.py                                  # backend + static UI checks
python3 tools/build_ui_data.py --check                    # embedded example data matches examples/
pip install playwright && playwright install chromium     # once, for the browser tests
python3 -m http.server 8000 &                             # from the repo root
python3 tests/ui/ui_v6.py http://localhost:8000/ui/       # v6 UI in Chromium emulation
```
- `ui_v6.py` checks:
  - zero network requests
  - Ask about this on 13 surfaces, plus the text-box fallback
  - verdict mapping
  - keyboard graph selection
  - 390 px layout and tap targets
  - reduced motion
  - the WebGL fallback
- It runs Chromium with `channel="chrome"`, so Google Chrome must be installed.
- The old `tests/ui/legacy/ui_r3.py` and `ui_r4.py` target the retired v5 UI and are not run.

## How it works
```
skills/*  ──(public data, when you run them)──▶  out/*.json  ──Open──▶  ui/
examples/*.json (synthetic) ──tools/build_ui_data.py──▶ ui/data/reports.js ──▶ ui/
```
- **Skills** (`skills/`):
  - `token-scan`, `wallet-scan`, `wallet-reputation`, `rug-replay`, `leaderboard`
  - `copy-network`, `shill-network`
  - `watch-token`, `threat-feed`
  - `promo-provenance`, `signals`, `solana-data`
- Each report carries an `assessment`: lead finding, severity, coverage and limits, findings tagged *observed*, *heuristic* or *inferred*, and next actions. If a provider is down, its values show as unknown, never as clean.
- **The UI makes no outbound network requests:**
  - **Local assets only:** it loads only its own files (HTML, JS, fonts, data).
  - **Same-origin only:** the CSP sets `connect-src 'self'`. Served statically (`python3 -m http.server`), the page never calls anything. Under `npx grok-the-block` it calls only the launcher's local `/api/` (loopback Host, same-origin Origin, a per-run token and a custom request header).
  - **Refresh runs in the launcher, not the page:** it uses HTTPS GETs to four allow-listed hosts (data-api.ecb.europa.eu, api.frankfurter.dev, fred.stlouisfed.org, publicreporting.cftc.gov) with no redirects and bounded retries, and only when you press Refresh.
  - **Vendored libraries:** three.js r164 and its post-processing passes are vendored in `ui/vendor/`.
  - **Self-hosted fonts:** the fonts are in `ui/fonts/`.
  - **Verified:** a Playwright test checks every request.
- **Plain JavaScript, no build step:** `index.html`, `app.js` and `stage.js`.
- **The skills do use the network:** they call public APIs when you run them. The UI never does.
- **Grok integration:** "Ask about this" and "Copy to Grok" copy a bounded prompt. Optional Connected Grok (launcher only, your own `XAI_API_KEY`, consent per question) is **UNVERIFIED** against the live xAI API. Grok can interpret evidence, but it can't change a detector's state: an answer that contradicts it is rejected (fail closed).

## Roadmap
- **More refreshable markets.** Refresh covers FX, energy and CFTC positioning. Metals, collectibles and the markets family stay on the snapshot. Live polling runs only in `signals.py watch`.
- **Hosted alerts.** No hosted service exists yet.
- **Measured accuracy.** The human-labelled evaluation has not started, so no accuracy is claimed.
- **Dedicated market views.** Non-crypto markets share the Signals view; Token, Wallet and Replay views are Solana-only.
- **More markets.** Non-US equities are not covered.
- **Physical-device testing** on iOS and Android.

## Project status and limitations
- **Research preview.** Local use: CONDITIONAL GO. Hosted or public alerts: **NO GO**. Provider rights, licensed latency, monitored delivery, and load and device testing are all outstanding.
- **Evaluation is unlabeled.** The Treasury evaluation roster and sample exist, but there are **0 human labels**. The reviewer gate needs two independent reviewers, an adjudicator, 12 vignettes each and a 25-item pilot, none of which has happened yet. **No precision, recall, hit rate or lead time has been measured.** Signal rankings are uncalibrated sorting aids. See [docs/review/ROUND9-RESULTS.md](docs/review/ROUND9-RESULTS.md) and [docs/review/FINDINGS.md](docs/review/FINDINGS.md).
- **Synthetic examples.** Everything bundled in `examples/` is invented (`$SYNTHING`, `$SYNBOT`, `$SYNFART`). It describes no real token or wallet.
- **No live feed.** Refresh is a single run that you start; nothing is scheduled. The UI's Live feed replays loaded reports. `signals.py watch` polls only when you run it. Its optional webhook delivery is at-least-once, deduplicated by `alertId` (not exactly-once). There is no hosted service.
- **Devices.** The UI is tested only in Chromium emulation (desktop, 320–390 px, reduced motion). It has not been tested on physical iOS or Android devices. CI is staged but inactive.
- **Data limits:**
  - Without a Helius key, busy tokens may not reach launch (`reachedLaunch: false`).
  - PnL is realized SOL flow in the analyzed window.
  - Leaderboard and reputation only know what this machine has scanned.
  - X data comes from samples.
  - Release-calendar BLS times are provisional unless `GTB_CONTACT` is set.
- **Footer links:** Risk disclosure and Methodology are placeholders.

## Data sources and provider rights
- **Solana:** public RPC, DexScreener, RugCheck, and Helius (optional).
- **Cross-market:** Polymarket, Kalshi, Yahoo/Nasdaq, Cboe delayed, Treasury.gov/FRED, OKX/Coinbase, DefiLlama.
- **Filings:** SEC EDGAR (opt-in).
- **Calendars:** Federal Reserve and BLS.
- **Rights are unverified.** Display and redistribution rights for each provider haven't been confirmed, so every row in the register is "unverified, needs review/permission".
- **The default posture is self-run:** each user runs the tool for their own analysis. There is no central rebroadcast.
- See [docs/PROVIDER-RIGHTS.md](docs/PROVIDER-RIGHTS.md).

## Licenses and third-party notices
- **Code:** MIT License, © 2026 Nikki (@varien). See [LICENSE](LICENSE).
- **three.js r164:** MIT, copied unmodified (`ui/vendor/three/`, `ui/licenses/three.js-r164-MIT.txt`).
- **Fonts:** Big Shoulders Display, Martian Mono and Noto Sans JP (subset to 危険注意), all under the SIL Open Font License 1.1, with their licence texts in `ui/licenses/`.
- **Notices:** a summary is in [ui/licenses/NOTICE-v6.md](ui/licenses/NOTICE-v6.md). The licences for the archived v5 UI (`ui/legacy/`) are kept in the same folder.
- **Asset manifest:** [docs/assets-manifest.json](docs/assets-manifest.json) lists each asset's SHA-256, source and status.

## Credits
Grok The Block grew out of [CryptOSINT](https://github.com/outerheaven199X/CryptOSINT) by Nikki ([@varien](https://x.com/varien)).

## Legal notice

- **Not advice.** Nothing in this software, its output or this repository is financial, investment, legal or tax advice.
- **No recommendation.** Nothing here is an offer, solicitation or recommendation to buy, sell or hold any asset, token or security.
- **Patterns, not accusations.** Signals and labels (such as "insider", "sniper", "coordinated" or "copy") are statistical and timing patterns in public data. They are not accusations of wrongdoing, and they are not claims about any person's identity, intent or control of any wallet or account.
- **May be wrong.** Output can be wrong, incomplete, delayed or stale. Providers fail, samples are partial, and no detection accuracy has been measured.
- **No warranty.** The software is provided **"AS IS", without warranty of any kind**, express or implied, including merchantability, fitness for a particular purpose and non-infringement. **In no event shall the authors or copyright holders be liable** for any claim, damages or other liability arising from the software or its use (see [LICENSE](LICENSE)).
- **Your responsibility.** Do your own research and consult a licensed professional before making any decision. You are responsible for your own decisions.
- **Third-party data** and trademarks belong to their respective owners. Use of any provider's data is subject to that provider's terms.
- **No affiliation.** This project is not affiliated with, endorsed by or sponsored by xAI, X, Solana, Polymarket, Kalshi, the SEC, the U.S. Bureau of Labor Statistics, the Federal Reserve or any exchange or data provider.
- **Local laws.** You are responsible for complying with the laws and regulations that apply to you, including rules on market data, privacy and the use of analysis like this.
