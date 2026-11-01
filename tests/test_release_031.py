"""0.3.1 static regression checks (no browser): version everywhere, release notes, and the four fixes present in the shipped UI
source. The behavioural checks are in tests/ui/ui_031.py and tests/e2e/acceptance_pack.py."""
import json, re, subprocess, sys
from pathlib import Path
R = Path(__file__).resolve().parents[1]
INV = (R / "ui/investigate.js").read_text(); IDX = (R / "ui/index.html").read_text()

def test_version_is_031_everywhere():
    assert json.loads((R / "packages/cli/package.json").read_text())["version"] == "0.3.1"
    ref = (R / "packages/cli/lib/refresh.mjs").read_text()
    assert "grok-the-block/0.3.1 (" in ref and "grok-the-block/0.3.0" not in ref and "launcher in 0.3.1;" in ref
    assert 'v == WANT == "0.3.1"' in (R / "tests/e2e/acceptance_pack.py").read_text()

def test_release_notes_031_first_and_complete():
    ch = (R / "packages/cli/CHANGELOG.md").read_text()
    heads = re.findall(r"^## (\S+)", ch, re.M)
    assert heads[:2] == ["0.3.1", "0.3.0"], heads[:3]
    sec = ch.split("## 0.3.0")[0]
    for w in ("Refreshed readings", "footer", "dataStatus", "bundled", "Not financial advice", "not published to npm"): assert w in sec, w
    rn = (R / "docs/releases/0.3.1.md").read_text()
    assert "0.3.1" in rn and "Not financial advice" in rn

def test_fix1_readings_rows_have_the_severity_square():
    f = INV[INV.index("function readingsCard()"):INV.index("function realGroups(")]
    assert 'data-state="${st}">${sevSq(o.severity)}<span class="eb">' in f

def test_fix2_short_viewport_footer_keeps_the_full_notice():
    m = re.search(r"@media \(min-width:768px\) and \(max-height:820px\)\{(footer\{display:grid.*?)\}\n", IDX)
    assert m and "footer p{grid-row:2;grid-column:1/-1" in m.group(1) and "font-size" not in m.group(1) and "display:none" not in m.group(1)
    assert "footer p{margin:0;flex:1 1 520px;font-size:11px;line-height:17px" in IDX            # v6 default layout untouched
    txt = re.search(r"<footer>(.*?)</footer>", IDX, re.S).group(1)
    for w in ("Not financial advice", "not financial, investment, legal or tax advice", "Do your own research and consult a licensed professional.", "Legal notice (README)", "Risk disclosure", "Methodology"): assert w in txt, w

def test_fix3_case_file_reports_data_status_and_never_calls_stale_fresh():
    f = INV[INV.index("function dataStatus(O)"):INV.index("const DS_SHORT")]
    live = f.index('"real-live-refreshed"')
    for st in ('"fixture-replay"', '"real-stale-carried"', '"real-stale-upstream"', '"real-unavailable"'): assert f.index(st) < live, st   # stale/fixture states are decided first
    assert 'f === "fresh" && R && !stale(O)' in f
    assert "dataStatus: ds.status, dataStatusLabel: ds.label, sourceAsOf: ds.sourceAsOf" in INV and 'observed: o.kind' in INV
    assert '["Data", d.evidence.dataStatusLabel || d.evidence.observed]' in INV

def test_fix4_bundled_rows_grouped_after_refresh_rows():
    f = INV[INV.index("function realGroups("):INV.index("function vPulse(")]
    assert f.index('data-group="refresh"') < f.index('data-group="bundled"')
    assert 'bundled: "bundled snapshot (cached, not refreshed)"' in INV and 'EV.refreshed ? "bundled" : "cached"' in INV

def test_index_html_sidecar_matches():
    want = (R / "ui/index.html.sha256").read_text().split()[0]
    import hashlib; assert hashlib.sha256((R / "ui/index.html").read_bytes()).hexdigest() == want

def test_no_threshold_changes_since_030():
    d = subprocess.run(["git", "-C", str(R), "diff", "202546a", "--", "packages/cli/lib/refresh.mjs", "lib/"], capture_output=True, text=True).stdout
    changed = [l for l in d.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    assert all("0.3.1" in l or "0.3.0" in l for l in changed), changed[:4]

if __name__ == "__main__":
    n = fails = 0
    for k, v in list(globals().items()):
        if k.startswith("test_") and callable(v):
            n += 1
            try: v(); print("ok  ", k)
            except Exception as e:  # noqa: BLE001
                fails += 1; print("FAIL", k, "--", type(e).__name__, str(e)[:200])
    print(f"release_031: {n - fails}/{n} passed")
    sys.exit(1 if fails else 0)
