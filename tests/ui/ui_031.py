"""0.3.1 regression suite (browser): the four layout/labelling bugs found while recording the 0.3.0 launch video.
  1. Pulse 'Refreshed readings' rows carry the severity square, so the text is not squeezed into the 8px column at 1280 wide.
  2. Short desktop viewports (1280x720): compact disclaimer footer, full not-financial-advice text, more room for the panel.
  3. Case files report the real data status (live-refreshed / stale upstream / carried / aged / bundled / FIXTURE), never 'fresh'
     for stale data, with the provider's as-of date.
  4. Pulse Real observations: rows from the refresh come first; bundled snapshot rows are grouped and labelled bundled.
Real launcher start() via tests/ui/inv_harness.mjs with GTB_REFRESH_FIXTURES (recorded responses, never the network) and the
LOCAL MOCK xAI (Grok key off). usage: ui_031.py [--shots DIR]"""
import json, shutil, subprocess, sys, tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright

R = Path(__file__).resolve().parents[2]
SHOTS = Path(sys.argv[sys.argv.index("--shots") + 1]) if "--shots" in sys.argv else None
GL = ["--use-gl=angle", "--use-angle=swiftshader", "--enable-unsafe-swiftshader"]
ok = fails = 0
def res(name, cond, info=""):
    global ok, fails
    ok += bool(cond); fails += (not cond)
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else " - " + str(info)[:400]), flush=True)
def shot(pg, name):
    if SHOTS: SHOTS.mkdir(parents=True, exist_ok=True); pg.screenshot(path=str(SHOTS / name))
def T(pg, sel): return pg.evaluate("(s) => { const e = document.querySelector(s); return e ? e.innerText : '' }", sel)
def E(pg, js, arg=None):
    """evaluate, but a missing API (e.g. running this suite against 0.3.0) is a FAIL, not a crash"""
    try: return pg.evaluate(js, arg)
    except Exception as e: return {"__error": str(e)[:160]}
def g_(d, *ks):
    for k in ks: d = d.get(k) if isinstance(d, dict) else None
    return d
def boot(pg, url): pg.goto(url); pg.wait_for_function("() => window.GTB && GTB.ready && GTB.inv", timeout=30000); pg.wait_for_timeout(600)
def harness(state, fixtures=None):
    p = subprocess.Popen(["node", str(R / "tests/ui/inv_harness.mjs"), "--state", state, "--key", "0"] + (["--fixtures", fixtures] if fixtures else []), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, cwd=str(R))
    return p, f"http://127.0.0.1:{json.loads(p.stdout.readline())['port']}/"
def stop(p):
    p.terminate()
    try: p.wait(5)
    except Exception: p.kill()
FOOT = "() => { const f = document.querySelector('footer'), p = document.getElementById('panel'), q = document.querySelector('footer p'), n = document.querySelector('footer .nfa'), L = [...document.querySelectorAll('footer .links a')]; const b = (e) => e.getBoundingClientRect(); return { f: Math.round(b(f).height), fb: Math.round(b(f).bottom), p: Math.round(b(p).height), font: getComputedStyle(q).fontSize, lh: getComputedStyle(q).lineHeight, nfaVis: b(n).height > 0 && b(n).top < innerHeight, links: L.map(a => [a.textContent, Math.round(b(a).height)]), text: f.innerText, ox: document.documentElement.scrollWidth - innerWidth, pinside: b(q).right <= innerWidth && b(q).left >= 0 }; }"
NFA_END = "Do your own research and consult a licensed professional."

# a recorded-response fixture with the last EUR/TRY fix moved +6%, so the refresh itself flags something (test data, labelled FIXTURE)
FX = Path(tempfile.mkdtemp(prefix="gtb031-fx-")) / "providers"; shutil.copytree(R / "packages/cli/test/fixtures/providers-20261101", FX)
L = (FX / "ecb.csv").read_text().strip().split("\n"); i = len(L) - 1
while ",TRY," not in L[i]: i -= 1
c = L[i].split(","); c[3] = str(round(float(c[3]) * 1.06, 4)); L[i] = ",".join(c); (FX / "ecb.csv").write_text("\n".join(L) + "\n")

with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", args=GL)
    # ---------- before any refresh: unchanged 0.3.0 behaviour (everything is the bundled snapshot, labelled cached) ----------
    st0 = tempfile.mkdtemp(prefix="gtb031-st0-"); p, url = harness(st0)
    try:
        ctx = b.new_context(viewport={"width": 1280, "height": 720}); pg = ctx.new_page(); boot(pg, url); pg.evaluate("() => GTB.go('pulse')"); pg.wait_for_timeout(500)
        pv = pg.evaluate("() => [...document.querySelectorAll('#pulseReal [data-pkey]')].map(e => e.dataset.prov)")
        res("no refresh: Real observations are ungrouped and all labelled cached (bundled snapshot)", pv and set(pv) == {"cached"} and pg.locator("#pulseReal [data-group]").count() == 0, set(pv))
        res("no refresh: no Refreshed readings card", pg.locator("#pulseReadings").count() == 0)
        ds = E(pg, "() => GTB.inv.dataStatus('fx:EUR/TRY:CHECKS')")
        res("no refresh: data status is real-cached-bundled with the provider date, not live", g_(ds, "status") == "real-cached-bundled" and g_(ds, "sourceAsOf") and "live" not in g_(ds, "label"), ds)
        g = pg.evaluate(FOOT)
        res("fix 2: 1280x720 footer <=130px (was 180), panel >=330px (was 283), text 11px", g["f"] <= 130 and g["p"] >= 330 and g["font"] == "11px", g)
        res("fix 2: 1280x720 full not-financial-advice text, label visible, all three links, no overflow", "NOT FINANCIAL ADVICE" in g["text"].upper() and NFA_END in g["text"] and "not financial" in g["text"] and g["nfaVis"] and len(g["links"]) == 3 and g["ox"] <= 0 and g["pinside"] and g["fb"] <= 720, g)
        shot(pg, "fix2-1280x720.png")
        for w, h, cap in [(1366, 768, 130), (1280, 800, 130), (1024, 768, 160)]:
            pg.set_viewport_size({"width": w, "height": h}); pg.wait_for_timeout(250); g = pg.evaluate(FOOT)
            res(f"fix 2: {w}x{h} compact footer (<= {cap}px) with the full disclaimer, no overflow", g["f"] <= cap and NFA_END in g["text"] and g["ox"] <= 0 and (w < 1100 or g["fb"] <= h), g)
        pg.set_viewport_size({"width": 1440, "height": 900}); pg.wait_for_timeout(250); g = pg.evaluate(FOOT)
        res("fix 2: tall desktop (1440x900) keeps the original v6 footer layout", g["f"] >= 140 and pg.evaluate("() => getComputedStyle(document.querySelector('footer')).display") == "flex", g)
        pg.evaluate("() => GTB.inv.open('fx:EUR/TRY:CHECKS')"); pg.wait_for_timeout(400)
        res("fix 3: investigation rail shows the data status (bundled snapshot) next to the kind", E(pg, "() => document.getElementById('invDataStatus').dataset.status") == "real-cached-bundled" and pg.evaluate("() => document.getElementById('invKind').dataset.kind") == "real-cached")
        ctx.close()
        for w, h in [(390, 844), (375, 667), (320, 568)]:
            ctx = b.new_context(viewport={"width": w, "height": h}, is_mobile=True, has_touch=True); pg = ctx.new_page(); boot(pg, url); pg.evaluate("() => GTB.go('pulse')"); pg.wait_for_timeout(400)
            g = pg.evaluate(FOOT)
            res(f"fix 2: {w}x{h} phone footer unchanged (flex, page scroll), full disclaimer, 44px links, no overflow", pg.evaluate("() => getComputedStyle(document.querySelector('footer')).display") == "flex" and NFA_END in g["text"] and all(hh >= 44 for _, hh in g["links"]) and g["ox"] <= 0, g)
            if w == 390: pg.evaluate("() => document.querySelector('footer').scrollIntoView({ block: 'end' })"); pg.wait_for_timeout(200); shot(pg, "fix2-390x844-footer.png")
            ctx.close()
    finally: stop(p)
    # ---------- after a FIXTURE refresh (recorded responses, EUR/TRY +6%) ----------
    st1 = tempfile.mkdtemp(prefix="gtb031-st1-"); p, url = harness(st1, str(FX))
    try:
        ctx = b.new_context(viewport={"width": 1280, "height": 720}, accept_downloads=True); pg = ctx.new_page(); boot(pg, url); pg.evaluate("() => GTB.go('pulse')"); pg.wait_for_timeout(400)
        with pg.expect_navigation(timeout=60000): pg.click("#pulseRefresh [data-refresh]")
        boot(pg, url); pg.evaluate("() => GTB.go('pulse')"); pg.wait_for_timeout(600)
        res("refresh ran as FIXTURE replay", pg.evaluate("() => !!(GTB.EV.refreshed && GTB.EV.refreshed.fixture)"))
        # fix 1
        rows = pg.evaluate("() => [...document.querySelectorAll('#pulseReadings .erow')].map(e => { const t = e.querySelector('.ti'), eb = e.querySelector('.eb'); return { first: e.firstElementChild.className, col: Math.round(eb.getBoundingClientRect().left - e.getBoundingClientRect().left), w: Math.round(t.getBoundingClientRect().width), h: Math.round(t.getBoundingClientRect().height) }; })")
        res("fix 1: every Refreshed readings row starts with the severity square", rows and all(r["first"] == "sq" for r in rows), rows[:3])
        res("fix 1: the reading text sits in the wide column at 1280 (not the 8px square column)", rows and all(r["col"] >= 16 and r["w"] > 200 and r["h"] < 120 for r in rows), rows[:3])
        pg.evaluate("() => { const p = document.getElementById('panel'), r = document.getElementById('pulseReadings'); p.scrollTop += r.getBoundingClientRect().top - p.getBoundingClientRect().top - 8; }"); pg.wait_for_timeout(200); shot(pg, "fix1-readings-1280x720.png")
        pg.evaluate("() => { document.getElementById('panel').scrollTop = 0; }")
        # fix 4
        grp = pg.evaluate("() => [...document.querySelectorAll('#pulseReal [data-group]')].map(e => [e.dataset.group, [...e.querySelectorAll('[data-pkey]')].map(r => [r.dataset.pkey.split(':')[0], r.dataset.prov])])")
        res("fix 4: Real observations are two groups, refresh first, then bundled", [g[0] for g in grp] == ["refresh", "bundled"], [g[0] for g in grp])
        fr = dict(grp).get("refresh", []); bn = dict(grp).get("bundled", [])
        res("fix 4: the refresh-flagged EUR/TRY move leads the list, labelled FIXTURE (never refreshed/live)", fr and fr[0][0] == "fx" and all(pv == "fixture" for _, pv in fr), fr)
        res("fix 4: bundled stablecoin/Polymarket/Kalshi rows are kept (not deleted) and labelled bundled", bn and {"stablecoins", "polymarket"} <= {m for m, _ in bn} and all(pv == "bundled" for _, pv in bn), sorted({m for m, _ in bn}))
        res("fix 4: bundled group and rows say 'bundled snapshot (cached, not refreshed)'", T(pg, "#pulseReal [data-group=bundled]").upper().count("BUNDLED SNAPSHOT (CACHED, NOT REFRESHED)") >= len(bn) and "FROM THE BUNDLED SNAPSHOT" in T(pg, "#pulseReal [data-group=bundled] .pgrp").upper(), T(pg, "#pulseReal [data-group=bundled] .pgrp"))
        res("fix 4: no row after a refresh is labelled plain 'cached' (current)", pg.locator("#pulseReal [data-prov='cached']").count() == 0)
        res("fix 4: severity filter still applies inside both groups", True if not pg.locator("[data-pf=sev][data-v=HIGH]").count() else (pg.click("[data-pf=sev][data-v=HIGH]") or pg.wait_for_timeout(200) or True) and all(x == "HIGH" for x in pg.evaluate("() => [...document.querySelectorAll('#pulseReal [data-pkey]')].map(r => GTB.inv.pulseItems().find(i => i.key === r.dataset.pkey).sev)")))
        pg.click("[data-pf=sev][data-v=all]") if pg.locator("[data-pf=sev][data-v=all]").count() else None; pg.wait_for_timeout(200)
        shot(pg, "fix4-pulse-1280x720.png")
        home = pg.evaluate("() => { GTB.go('home'); return new Promise(r => setTimeout(() => r([...document.querySelectorAll('#hpulse .pr .pa')].map(e => e.textContent)), 400)); }")
        res("fix 4: home 'What's weird' puts the refresh row first and labels bundled rows bundled", home and home[0].startswith("fixture") and all(h.split(" ·")[0] in ("fixture", "bundled") for h in home), home)
        # fix 3
        KF = pg.evaluate("() => [...GTB.inv.index().values()].find(o => o.stableId === 'fx:EUR/TRY' && !o.quiet).key")
        KQ = pg.evaluate("() => [...GTB.inv.index().values()].find(o => o.module === 'fx' && o.quiet && o.severity === 'NONE' && o.set === 'live').key")
        pg.evaluate("(k) => GTB.inv.open(k)", KF); pg.wait_for_timeout(600)
        res("fix 3: investigation rail shows the FIXTURE data status after a fixture refresh", E(pg, "() => (document.getElementById('invDataStatus') || { dataset: {} }).dataset.status") == "fixture-replay")
        dj = E(pg, "(k) => GTB.inv.dossier(k).then(x => x.json)", KF)
        res("fix 3: FIXTURE case file: dataStatus fixture-replay, kind fixture-test, provider date and run id", g_(dj, "evidence", "dataStatus") == "fixture-replay" and g_(dj, "evidence", "observed") == "fixture-test" and g_(dj, "evidence", "sourceAsOf") == "2026-10-30" and g_(dj, "evidence", "refreshRun") == g_(dj, "snapshot", "runId"), g_(dj, "evidence"))
        mx = E(pg, """(K) => { const E = GTB.EV, cov = E.live.coverage.find(c => c.module === 'fx'), sig = GTB_EV.EV_SIGS.find(x => x.s.key === K).s, ds = () => GTB.inv.dataStatus(K);
          const out = {}; const keep = [E.refreshed.fixture, cov.freshness, sig.ingestedAt];
          const sfx = sig.fixture; delete sig.fixture; E.refreshed.fixture = false; cov.freshness = 'fresh'; out.fresh = ds();
          cov.freshness = 'upstream-stale'; out.upstream = ds();
          cov.freshness = 'carried-after-failure'; out.carried = ds();
          cov.freshness = 'unavailable'; out.unavailable = ds();
          cov.freshness = 'fresh'; sig.ingestedAt = new Date(Date.now() - 10 * 86400e3).toISOString(); out.aged = ds();
          cov.freshness = 'bundled-snapshot'; out.bundled = ds();
          E.refreshed.fixture = true; cov.freshness = 'fresh'; sig.ingestedAt = keep[2]; out.fixture = ds();
          E.refreshed.fixture = false; sig.fixture = sfx; out.sigFixture = ds();
          E.refreshed.fixture = false; return out; }""", KQ)
        want = {"fresh": "real-live-refreshed", "upstream": "real-stale-upstream", "carried": "real-stale-carried", "unavailable": "real-unavailable", "aged": "real-stale-aged", "bundled": "real-cached-bundled", "fixture": "fixture-replay", "sigFixture": "fixture-replay"}
        if "__error" in mx: mx = {k: {"status": None, "label": "", "sourceAsOf": None} for k in want}
        res("fix 3: data status follows the source freshness exactly (fresh/upstream-stale/carried/unavailable/aged/bundled/fixture)", {k: v["status"] for k, v in mx.items()} == want, {k: v["status"] for k, v in mx.items()})
        res("fix 3: only a fresh, non-fixture, in-cadence reading is ever called live; every stale state says stale/not fresh", "live-refreshed" in mx["fresh"]["label"] and all("live-refreshed" not in mx[k]["label"] and mx[k]["status"] != "real-live-refreshed" for k in want if k != "fresh") and all("stale" in mx[k]["label"] for k in ("upstream", "carried")) and "not fresh" in mx["aged"]["label"], {k: v["label"][:90] for k, v in mx.items()})
        res("fix 3: every status carries the provider as-of date", all(v["sourceAsOf"] == "2026-10-30" for v in mx.values()), {k: v["sourceAsOf"] for k, v in mx.items()})
        # the simulated live-refreshed state (fixture flag cleared in-page above) exports with the right label in the HTML too
        pg.evaluate("(k) => { const c = GTB.EV.live.coverage.find(c => c.module === 'fx'); c.freshness = 'fresh'; delete GTB_EV.EV_SIGS.find(x => x.s.key === k).s.fixture; }", KQ)
        h = E(pg, "(k) => GTB.inv.dossier(k).then(x => ({ ht: x.html, ev: x.json.evidence }))", KQ); h = h if "ht" in h else {"ht": "", "ev": {}}
        res("fix 3: case-file HTML 'Data' row shows the live-refreshed status with the provider date (not 'real-cached')", h["ev"].get("dataStatus") == "real-live-refreshed" and "<th>Data</th><td>real data, live-refreshed" in h["ht"] and "provider as of 2026-10-30" in h["ht"] and "<th>Data</th><td>real-cached</td>" not in h["ht"], h["ev"])
        pg.evaluate("() => { const c = GTB.EV.live.coverage.find(c => c.module === 'fx'); c.freshness = 'upstream-stale'; }")
        h = E(pg, "(k) => GTB.inv.dossier(k).then(x => ({ ht: x.html, ev: x.json.evidence }))", KQ); h = h if "ht" in h else {"ht": "", "ev": {}}
        res("fix 3: stale upstream exports as stale, never fresh or live", h["ev"].get("dataStatus") == "real-stale-upstream" and "stale upstream" in h["ht"] and "live-refreshed" not in h["ht"], h["ev"])
        ctx.close()
        ctx = b.new_context(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True); pg = ctx.new_page(); boot(pg, url); pg.evaluate("() => GTB.go('pulse')"); pg.wait_for_timeout(500)
        top = pg.evaluate("() => { const r = document.querySelector('#pulseReal [data-inv]'); return r ? r.getBoundingClientRect().top : 9999 }")
        res("390px after refresh: groups render, first observation on the first screen, no overflow", pg.locator("#pulseReal [data-group=refresh]").count() == 1 and top < 844 and pg.evaluate("() => document.documentElement.scrollWidth - innerWidth") <= 0, top)
        shot(pg, "fix4-pulse-390x844.png")
        rr = pg.evaluate("() => [...document.querySelectorAll('#pulseReadings .erow')].map(e => e.firstElementChild.className)")
        res("390px: Refreshed readings rows keep the severity square", rr and all(x == "sq" for x in rr), rr)
        ctx.close()
    finally: stop(p)
    b.close()
shutil.rmtree(FX.parent, ignore_errors=True)
print(f"ui_031: {ok}/{ok + fails} passed")
sys.exit(1 if fails else 0)
