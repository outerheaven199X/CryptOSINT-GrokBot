"""0.3.1 end-to-end acceptance (0.3.0 checks plus the 0.3.1 regression checks) against the ACTUAL npm pack tarball installed into a clean temporary prefix (Linux box).
Step A uses the LIVE keyless providers (real network). Step B restarts the same install with GTB_REFRESH_FIXTURES pointing at a
FIXTURE second snapshot (the recorded real responses with the last EUR/TRY fix moved +6% and the CFTC file removed) to show a
genuine change, an unchanged reading and a failed provider; everything from step B is labelled FIXTURE in the UI and files.
usage: acceptance.py TARBALL REPO_ROOT OUTDIR"""
import json, os, re, shutil, subprocess, sys, tempfile, time, hashlib
from pathlib import Path
from playwright.sync_api import sync_playwright
TGZ, REPO, OUT = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
SH = OUT / "shots"; SH.mkdir(parents=True, exist_ok=True)
GL = ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"]
ok = fails = 0; LOG = []
def res(n, c, info=""):
    global ok, fails
    ok += bool(c); fails += (not c); line = ("PASS " if c else "FAIL ") + n + ("" if c else " - " + str(info)[:400]); print(line, flush=True); LOG.append(line)
def note(s): print("NOTE " + s, flush=True); LOG.append("NOTE " + s)
T = Path(tempfile.mkdtemp(prefix="gtb031-acc-")); PFX, CACHE, HOME, STATE = T / "prefix", T / "npm-cache", T / "home", T / "state"
for d in (PFX, CACHE, HOME): d.mkdir()
env0 = {"PATH": os.environ["PATH"], "HOME": str(HOME), "npm_config_cache": str(CACHE), "npm_config_prefix": str(PFX), "npm_config_userconfig": str(T / "npmrc-empty"), "npm_config_update_notifier": "false", "npm_config_fund": "false", "npm_config_audit": "false"}
(T / "npmrc-empty").write_text("")
note(f"tarball {TGZ.name} sha256 {hashlib.sha256(TGZ.read_bytes()).hexdigest()}")
ins = subprocess.run(["npm", "install", "-g", "--ignore-scripts", str(TGZ)], env=env0, capture_output=True, text=True, timeout=300)
BIN = PFX / "bin" / "grok-the-block"
res("install: npm install -g of the tarball into a clean prefix and cache (no clone, no Python)", ins.returncode == 0 and BIN.exists(), ins.stderr[-400:])
pkgdir = PFX / "lib" / "node_modules" / "grok-the-block"
res("install: zero dependencies installed (node_modules contains only grok-the-block)", sorted(os.listdir(PFX / "lib" / "node_modules")) == ["grok-the-block"] and not (pkgdir / "node_modules").exists())
v = subprocess.run([str(BIN), "--version"], env=env0, capture_output=True, text=True).stdout.strip()
WANT = json.loads((REPO / "packages/cli/package.json").read_text())["version"]
res(f"installed version is {WANT} (the repo package.json)", v == WANT == "0.3.1", v)

def launch(extra=None):
    e = dict(env0, GTB_STATE_DIR=str(STATE)); e.update(extra or {})
    p = subprocess.Popen([str(BIN), "--no-open"], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = []
    for _ in range(40):
        l = p.stdout.readline(); lines.append(l)
        m = re.search(r"http://127\.0\.0\.1:\d+/", l)
        if m:
            for _ in range(4):                                      # preview notice, fixture-mode line (if any), then the Grok status line
                l = p.stdout.readline(); lines.append(l)
                if l.startswith("Grok") or not l: break
            return p, m.group(0), lines
    raise SystemExit("launcher did not start: " + "".join(lines))
def stop(p):
    p.terminate()
    try: p.wait(5)
    except Exception: p.kill()
def boot(pg, url):
    pg.goto(url); pg.wait_for_function("window.GTB&&GTB.ready&&GTB.inv", timeout=30000); pg.wait_for_timeout(500)
def T_(pg, s): return pg.evaluate("(s)=>{const e=document.querySelector(s);return e?e.textContent:''}", s)
def export_json(pg):
    with pg.expect_download() as d: pg.click("#invJson")
    return json.loads(Path(d.value.path()).read_text())

fixB = T / "fixture-B"; shutil.copytree(REPO / "packages/cli/test/fixtures/providers-20261101", fixB)
L = (fixB / "ecb.csv").read_text().strip().split("\n"); i = len(L) - 1
while ",TRY," not in L[i]: i -= 1
c = L[i].split(","); old = c[3]; c[3] = str(round(float(c[3]) * 1.06, 4)); L[i] = ",".join(c); (fixB / "ecb.csv").write_text("\n".join(L) + "\n"); (fixB / "cftc.json").unlink()
note(f"FIXTURE B: copy of the recorded real responses; EUR/TRY {c[2]} {old} -> {c[3]} (+6%); cftc.json removed (simulated CFTC failure)")

with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", args=GL)
    # ---------------- A: live keyless refresh ----------------
    p, url, lines = launch(); note("launcher A: " + " | ".join(x.strip() for x in lines if x.strip()))
    try:
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True); pg = ctx.new_page(); off = []
        pg.on("request", lambda r: (not r.url.startswith((url.rstrip("/"), "data:", "blob:"))) and off.append(r.url))
        boot(pg, url); pg.evaluate("GTB.go('pulse')"); pg.wait_for_timeout(600)
        res("A: Pulse opens with a Refresh button and the bundled snapshot", pg.locator("#pRefresh").count() == 1 and "Bundled snapshot" in T_(pg, "#pulseRefresh"))
        pg.screenshot(path=str(SH / "acc-01-pulse-before-refresh.png"))
        t0 = time.time()
        with pg.expect_navigation(timeout=180000): pg.click("#pRefresh")
        pg.wait_for_function("window.GTB&&GTB.ready&&GTB.inv", timeout=30000); pg.evaluate("GTB.go('pulse')"); pg.wait_for_timeout(800)
        note(f"A: live refresh took {time.time() - t0:.1f}s")
        units = pg.evaluate("[...document.querySelectorAll('#pulseRefresh .rrun')].map(e=>({u:e.dataset.unit,o:e.dataset.outcome,f:e.dataset.freshness,t:e.textContent}))")
        note("A units: " + json.dumps(units))
        E = pg.evaluate("(()=>{const E=GTB.EV;return {r:E.refreshed,cov:(E.live.coverage||[]).map(c=>({m:c.module,st:c.status,f:c.freshness,a:c.sourceAsOf,i:c.ingestedAt,via:c.via}))}})()")
        note("A coverage: " + json.dumps(E["cov"]))
        live = {u["u"]: u for u in units}
        res("A: live refresh ran (not fixture) and all four refreshable units have an outcome", E["r"] and not E["r"]["fixture"] and all(k in live and live[k]["o"] in ("fetched", "failed-carried", "failed-unavailable") for k in ("fx", "fx-h10", "energy", "cot")), units)
        res("A: every fetched unit carries the provider's own date (sourceAsOf) and a fetch time; freshness is fresh or upstream-stale, never invented", all(c["a"] and c["i"] and c["f"] in ("fresh", "upstream-stale") for c in E["cov"] if c["m"] in ("fx", "fx-h10", "energy", "cot") and live.get(c["m"], {}).get("o") == "fetched"), E["cov"])
        res("A: modules without a keyless provider stay on the bundled snapshot", all(c["f"] == "bundled-snapshot" for c in E["cov"] if c["m"] in ("metals", "mtg", "cs2")), E["cov"])
        nread = pg.locator("#pulseReadings [data-prov='refreshed'] [data-inv]").count()
        res("A: Pulse lists real refreshed readings (labelled refreshed, with source dates), none labelled fixture", nread >= 1 and pg.locator("#panel [data-prov='fixture']").count() == 0 and "source as of 20" in T_(pg, "#pulseReadings"), T_(pg, "#pulseReadings")[:300])
        pg.screenshot(path=str(SH / "acc-02-pulse-after-live-refresh.png"))
        # 0.3.1 fix 1: every Refreshed readings row starts with its severity square, so the text column is not squeezed
        rr = pg.evaluate("[...document.querySelectorAll('#pulseReadings .erow')].map(e=>[e.firstElementChild.className, Math.round(e.querySelector('.ti').getBoundingClientRect().width)])")
        res("A 0.3.1: Refreshed readings rows have the severity square and a full-width text column", rr and all(c == "sq" and w > 150 for c, w in rr), rr)
        # 0.3.1 fix 4: after a live refresh, nothing in Real observations is labelled current unless the refresh fetched it
        pv = pg.evaluate("[...document.querySelectorAll('#pulseReal [data-pkey]')].map(e=>[e.dataset.pkey.split(':')[0], e.dataset.prov, e.closest('[data-group]') ? e.closest('[data-group]').dataset.group : null])")
        grp = pg.evaluate("[...document.querySelectorAll('#pulseReal [data-group]')].map(e=>e.dataset.group)")
        res("A 0.3.1: Real observations: refreshed group first, bundled stablecoin/prediction rows grouped and labelled bundled, none 'cached'", grp[:1] == ["refresh"] and pv and all((g == "bundled") == (p == "bundled") and p != "cached" for m, p, g in pv) and all(p == "bundled" for m, p, g in pv if m in ("stablecoins", "polymarket", "kalshi")) and ("BUNDLED SNAPSHOT (CACHED, NOT REFRESHED)" in T_(pg, "#pulseReal").upper() if any(p == "bundled" for m, p, g in pv) else True), (grp, pv[:6]))
        pg.click("#pulseReadings [data-inv] >> nth=0"); pg.wait_for_timeout(600)
        first = pg.evaluate("GTB.inv.IV.ref")
        res("A: investigate a refreshed reading: detector state and source date shown, no FIXTURE banner", "Source as of" in T_(pg, "#panel") and "FIXTURE" not in T_(pg, "#panel"), T_(pg, "#panel")[:300])
        pg.screenshot(path=str(SH / "acc-03-investigate-live.png"))
        d1 = export_json(pg); pg.wait_for_timeout(1200); d2 = export_json(pg)
        res("A: case file is reproducible within a session (same contentSha256 and exportSha256)", d1["contentSha256"] == d2["contentSha256"] and d1["exportSha256"] == d2["exportSha256"], (d1.get("contentSha256"), d2.get("contentSha256")))
        # 0.3.1 fix 3: the case file says what the data is: live-refreshed only when the source's coverage is fresh, never for stale data
        covf = {c["m"]: c["f"] for c in E["cov"]}; mod = d1["observations"][0]["module"]; want = {"fresh": "real-live-refreshed", "upstream-stale": "real-stale-upstream", "carried-after-failure": "real-stale-carried"}.get(covf.get(mod), "real-cached-bundled")
        res("A 0.3.1: case file data status matches the source freshness (live-refreshed only if fresh) with the provider as-of date", d1["evidence"]["dataStatus"] == want and d1["evidence"]["sourceAsOf"] and d1["evidence"]["observed"] == "real-cached" and (want != "real-live-refreshed" or d1["evidence"]["refreshRun"] == E["r"]["runId"]), (mod, covf.get(mod), d1.get("evidence")))
        res("A: case file records the refreshed snapshot (run id, not fixture, provider date)", d1["snapshot"]["runId"] == E["r"]["runId"] and d1["snapshot"]["fixture"] is False and d1["snapshot"].get("sourceAsOf"), d1.get("snapshot"))
        (OUT / "case-A-live.json").write_text(json.dumps(d1, indent=2))
        pg.click("#invWatch"); pg.wait_for_timeout(500)
        for k in ("fx:EUR/TRY:CHECKS", "cot:Gold futures (COMEX):CHECKS"):
            if pg.evaluate(f"GTB.inv.index().has({json.dumps(k)})"):
                pg.evaluate(f"GTB.inv.open({json.dumps(k)})"); pg.wait_for_timeout(500); pg.click("#invWatch"); pg.wait_for_timeout(500)
            else: note("not in the index: " + k)
        pg.evaluate("GTB.go('watch')"); pg.wait_for_timeout(700)
        wids = pg.evaluate("[...document.querySelectorAll('#watchList [data-wid]')].map(e=>e.dataset.wid)")
        res("A: watchlist holds the investigated reading plus EUR/TRY and COT gold", len(wids) >= 2 and "fx:EUR/TRY" in wids, wids)
        pg.check("#wNotify"); pg.wait_for_timeout(300)
        pg.screenshot(path=str(SH / "acc-04-watchlist-after-live.png"))
        # reload: a fresh page session gives the same contentSha256 (generatedAt differs)
        pg.reload(); pg.wait_for_function("window.GTB&&GTB.ready&&GTB.inv", timeout=30000); pg.evaluate(f"GTB.inv.open({json.dumps(first)})"); pg.wait_for_timeout(600)
        d3 = export_json(pg)
        res("A: re-exporting after a reload reproduces contentSha256 exactly", d3["contentSha256"] == d1["contentSha256"], (d3["contentSha256"], d1["contentSha256"], d3["generatedAt"], d1["generatedAt"]))
        res("A: the page made no off-origin requests (providers are called by the launcher)", not off, off[:3])
        ctx.close()
    finally: stop(p)
    rlog = [json.loads(x) for x in (STATE / "snapshot" / "refresh-log.jsonl").read_text().splitlines() if x.strip()]
    note("A refresh-log: " + json.dumps(rlog[-1])[:1500])
    # ---------------- B: FIXTURE second snapshot ----------------
    p, url, lines = launch({"GTB_REFRESH_FIXTURES": str(fixB)}); note("launcher B: " + " | ".join(x.strip() for x in lines if x.strip()))
    try:
        res("B: launcher announces FIXTURE replay mode", any("FIXTURE" in x for x in lines), lines)
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True); pg = ctx.new_page(); boot(pg, url)
        pg.evaluate("GTB.go('watch')"); pg.wait_for_timeout(600)
        with pg.expect_navigation(timeout=120000): pg.click("#watchRefresh [data-refresh]")
        pg.wait_for_function("window.GTB&&GTB.ready&&GTB.inv", timeout=30000); pg.evaluate("GTB.go('watch')"); pg.wait_for_timeout(900)
        st = pg.evaluate("Object.fromEntries([...document.querySelectorAll('#watchList [data-wid]')].map(e=>[e.dataset.wid,{s:e.querySelector('.wst').dataset.state,t:e.textContent}]))")
        note("B watch states: " + json.dumps({k: v["s"] for k, v in st.items()}))
        tr = st.get("fx:EUR/TRY", {})
        res("B: EUR/TRY reports a genuine change, labelled FIXTURE, with evidence id, source and source date", tr.get("s") == "changed" and "FIXTURE" in tr.get("t", "") and "MOVE_VS_REALIZED_VOL" in tr.get("t", "") and "2026-10-30" in tr.get("t", ""), tr.get("t", "")[:400])
        cot = [v for k, v in st.items() if k.startswith("cot:")]
        res("B: the CFTC reading is unknown/stale after the failed provider, never quiet or unchanged", cot and all(v["s"] in ("unknown", "stale") for v in cot), [v["s"] for v in cot])
        others = [v["s"] for k, v in st.items() if k not in ("fx:EUR/TRY",) and not k.startswith("cot:")]
        note("B other watched states: " + json.dumps(others))
        res("B: notices card lists exactly one evidence-only change notice for EUR/TRY", pg.locator("#watchNotices [data-notice]").count() == 1 and "EUR/TRY" in T_(pg, "#watchNotices"), T_(pg, "#watchNotices")[:300])
        pg.screenshot(path=str(SH / "acc-05-watchlist-after-fixture-change.png"), full_page=True)
        pg.evaluate("GTB.go('pulse')"); pg.wait_for_timeout(700)
        res("B: the flagged EUR/TRY move appears in Pulse labelled FIXTURE, never refreshed/live", pg.locator("#pulseReal [data-prov='fixture']").count() >= 1 and pg.locator("#panel [data-prov='refreshed']").count() == 0)
        res("B: Pulse shows the CFTC failure as carried/unknown, not quiet", "cot" in T_(pg, "#pulseRefresh") and pg.locator("#pulseRefresh .rrun[data-unit='cot'][data-outcome^='failed']").count() == 1, T_(pg, "#pulseRefresh")[:300])
        pg.screenshot(path=str(SH / "acc-06-pulse-after-fixture-change.png"))
        pg.click("#pulseReal [data-prov='fixture'] [data-inv] >> nth=0"); pg.wait_for_timeout(600)
        res("B: investigating the fixture observation shows the FIXTURE banner and the flagged state", "FIXTURE" in T_(pg, "#panel") and "flagged by the detector" in T_(pg, "#panel"), T_(pg, "#panel")[:300])
        pg.screenshot(path=str(SH / "acc-07-investigate-fixture-change.png"))
        dB = export_json(pg); (OUT / "case-B-fixture.json").write_text(json.dumps(dB, indent=2))
        res("B: exported case file is marked FIXTURE (snapshot.fixture true, observation kind fixture-test, data status fixture-replay)", dB["snapshot"]["fixture"] is True and dB["evidence"]["observed"] == "fixture-test" and dB["evidence"]["dataStatus"] == "fixture-replay", (dB.get("snapshot"), dB.get("evidence")))
        # 0.3.1 fix 2: at 1280x720 the footer is compact and the full not-financial-advice notice is present
        pg.set_viewport_size({"width": 1280, "height": 720}); pg.wait_for_timeout(400)
        fg = pg.evaluate("(()=>{const f=document.querySelector('footer').getBoundingClientRect(),p=document.getElementById('panel').getBoundingClientRect();return {f:Math.round(f.height),p:Math.round(p.height),t:document.querySelector('footer').innerText}})()")
        res("B 0.3.1: at 1280x720 the footer is <=130px, the panel >=320px, and the full disclaimer is present", fg["f"] <= 130 and fg["p"] >= 320 and "NOT FINANCIAL ADVICE" in fg["t"].upper() and "Do your own research and consult a licensed professional." in fg["t"], fg)
        ctx.close()
    finally: stop(p)
    b.close()
hist = (STATE / "snapshot" / "history.jsonl").read_text().splitlines()
res("state: history keeps both runs (append-only)", len({json.loads(x).get("run") for x in hist}) >= 2, len(hist))
res("state: no key, token or credential-like string in the state dir", not re.search(r"xai-|Bearer |api[_-]?key", "".join(f.read_text(errors="ignore") for f in STATE.rglob("*") if f.is_file()), re.I))
print(f"acceptance: {ok}/{ok + fails} passed"); (OUT / "acceptance-summary.json").write_text(json.dumps({"passed": ok, "total": ok + fails, "tmp": str(T)}))
sys.exit(1 if fails else 0)
