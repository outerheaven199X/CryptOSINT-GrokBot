# grok-the-block

**Grok the Block: The Best Way To Lose All Your Money**

Local research preview of Grok The Block. One command starts a server on `127.0.0.1` and opens the bundled browser UI: Pulse, Investigations, watchlists and a user-started Refresh of keyless public data. Not financial advice.

```
npx grok-the-block            # OS-assigned port, opens your browser
npx grok-the-block --no-open  # print the URL only
npx grok-the-block --port 8000
```

- No wallet, sign-in, telemetry, install hooks or runtime dependencies. Node >= 22.14.0.
- Serves only the files in `dist/ui/` (GET/HEAD), plus a small same-origin JSON API under `/api/` (POST only, loopback Host and same-origin Origin required, per-run token, 64 KB bodies). No CORS, cannot be framed.
- The browser UI talks only to that local API (CSP `connect-src 'self'`). Data starts as the bundled cached snapshot plus labelled synthetic examples. Nothing refreshes in the background.
- **Refresh (only when you press it).** Press Refresh in Pulse or the Watchlist and the launcher fetches keyless public data, runs the same detectors and thresholds as the Python skills, and reloads the page:

  | Provider | Fetches | Key | Limits |
  |---|---|---|---|
  | ECB SDMX (`data-api.ecb.europa.eu`) | Daily reference rates for 16 currencies against EUR, since April | none | Business days only; published around 16:00 CET |
  | Frankfurter (`api.frankfurter.dev`) | The same ECB rates; used only if the ECB request fails | none | Unofficial mirror of the ECB, so the same cadence |
  | FRED fredgraph CSV (`fred.stlouisfed.org`) | DEXUSEU (H.10 USD/EUR fix for the cross-check), DCOILWTICO, DCOILBRENTEU, DHHNGSP (EIA spot) | none | H.10 is published weekly; EIA spot lags by about a week |
  | CFTC Socrata `6dca-aqww` (`publicreporting.cftc.gov`) | Legacy futures-only COT for gold, silver, WTI, wheat, corn, soybeans, coffee and cocoa | none | Weekly (Tuesday positions, published Friday) |

  Metals ETF proxies, Magic and CS2 stay on the bundled snapshot.

  Every reading keeps the provider's own date (`sourceAsOf`) and the time it was fetched (`ingestedAt`). When the provider's date is older than its cadence allows, the reading is **upstream-stale**, never fresh. When a provider fails, its last good reading is carried as **stale** with the error category (for example `network`, `timeout`, `html_error_page` or `http_4xx`), never as quiet.

  The launcher makes HTTPS GETs only to the four hosts above: no redirects, an 8 MB cap per response, 30 s timeouts, and up to 3 attempts on 429/5xx. One refresh runs at a time, behind a lock. The refreshed snapshot, the previous one, an append-only observation history and a refresh log live in the state directory. Nothing else is written.
- **Fixture replay (testing).** `GTB_REFRESH_FIXTURES=/abs/path` replays recorded provider responses instead of the network. Everything it produces is labelled FIXTURE in the UI and in case files.
- Investigate any loaded observation: an evidence-only case file works offline (export HTML or JSON, or print to PDF; the file carries a `contentSha256` over everything except its generation time), and "Copy to Grok" copies a bounded prompt.
- Optional Connected Grok: `XAI_API_KEY=... npx grok-the-block`, or paste a key for the session only. The key stays in the launcher process, is never written to disk and never reaches the page. Each question shows the exact evidence packet and asks for consent; xAI bills your account for tokens and search calls. The live xAI path is implemented against the documented Responses API but is UNVERIFIED (tested only against a local mock).
- **Watchlist.** Stored in a per-user state directory (`GTB_STATE_DIR`, or the OS default such as `~/.local/state/grok-the-block`), never inside the package. Each Refresh compares every watched item with its last reading and records whether it changed, is unchanged, is stale or is unknown, with the source, both dates and the checks that are still unknown. A failed provider never overwrites the baseline. Notices are evidence-only and shown only in the app. Clear the list from the Watchlist view.
- **Evidence integrity.** The Observed section of a case file is always built from the detector's own output. Optional Grok can interpret it but can't change it: an answer that contradicts the detector state (calls a quiet reading flagged, invents a severity, says stale data is live) is rejected whole and the local evidence summary is shown instead. Invented numbers and misattributed evidence are dropped item by item.
- Card Explorer shows text cards: card artwork is not included in the npm package. Images only appear when you run the app from a clone of the GitHub repo and run its optional `python3 tools/sync_tcg_art.py` there.
- Ctrl+C stops it. Not financial advice.
