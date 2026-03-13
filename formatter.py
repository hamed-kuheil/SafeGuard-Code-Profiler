"""
formatter.py — SafeGuard-Code Profiler
Handles all output: colorized CLI, JSON report, and HTML report.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# ─── Colorama (graceful fallback if not installed) ────────────────────────────
try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Dummy()

# ─── Severity → Color mapping ─────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": Fore.RED    + Style.BRIGHT,
    "HIGH":     Fore.YELLOW + Style.BRIGHT,
    "MEDIUM":   Fore.CYAN,
    "LOW":      Fore.WHITE,
    "INFO":     Fore.GREEN,
}

CAT_ICON = {
    "efficiency": "⚡",
    "security":   "🔒",
    "ethics":     "🧭",
}

# ─── ASCII Art Header ─────────────────────────────────────────────────────────
BANNER = r"""
  ____         __       ____                        _
 / ___|  __ _ / _| ___ / ___|_   _  __ _ _ __ __| |
 \___ \ / _` | |_ / _ \ |  _| | | |/ _` | '__/ _` |
  ___) | (_| |  _|  __/ |_| | |_| | (_| | | | (_| |
 |____/ \__,_|_|  \___|\____|\__,_|\__,_|_|  \__,_|

  +-+-+-+ +-+-+-+-+-+-+-+
  |C|o|d|e| |P|r|o|f|i|l|e|r|
  +-+-+-+ +-+-+-+-+-+-+-+
  [ Resource Efficiency · Security · AI Ethics ]
"""

DIVIDER     = Fore.CYAN + "─" * 72 + Style.RESET_ALL if HAS_COLOR else "─" * 72
THIN_DIV    = Fore.WHITE + "· " * 36 + Style.RESET_ALL if HAS_COLOR else "· " * 36


def _c(text: str, color: str) -> str:
    return color + text + Style.RESET_ALL if HAS_COLOR else text


def print_banner():
    print(_c(BANNER, Fore.CYAN + Style.BRIGHT))
    print(_c(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", Fore.WHITE))


def print_file_result(result: dict, verbose: bool = False):
    """Pretty-print a single file's scan result to stdout."""
    if "error" in result:
        print(_c(f"  ✗ ERROR: {result['error']}", Fore.RED))
        return

    filepath  = result["filepath"]
    language  = result["language"].upper()
    eff_score = result["efficiency_score"]
    eth_score = result["ethical_score"]
    findings  = result["findings"]
    total_lines = result["total_lines"]
    summary   = result["summary"]

    print(DIVIDER)
    print(_c(f"  📄 {filepath}", Fore.WHITE + Style.BRIGHT))
    print(_c(f"     Language: {language}  |  Lines: {total_lines}  |  Findings: {len(findings)}", Fore.WHITE))

    # ── Score bars ────────────────────────────────────────────────────────────
    print()
    _print_score_bar("Resource Efficiency", eff_score)
    _print_score_bar("Ethical Safety     ", eth_score)

    # ── Category breakdown ────────────────────────────────────────────────────
    if any(summary.get(k, 0) > 0 for k in ["efficiency", "security", "ethics"]):
        parts = []
        for cat in ["efficiency", "security", "ethics"]:
            n = summary.get(cat, 0)
            if n:
                parts.append(f"{CAT_ICON.get(cat,'')} {cat.capitalize()}: {n}")
        print(_c("  " + "  |  ".join(parts), Fore.WHITE))

    # ── Findings ──────────────────────────────────────────────────────────────
    if findings:
        print()
        for idx, f in enumerate(findings, 1):
            sev   = f["severity"]
            color = SEV_COLOR.get(sev, Fore.WHITE)
            icon  = CAT_ICON.get(f["category"], "•")
            print(_c(f"  [{idx:02d}] {icon} [{sev}] {f['rule_id']} — {f['name']}", color))
            print(_c(f"       Line {f['line']}: {f['snippet']}", Fore.WHITE))
            if verbose:
                print(_c(f"       ↳ {f['message']}", Fore.WHITE + Style.DIM))
            else:
                print(_c(f"       ↳ {f['message']}", Fore.WHITE))
            print()
    else:
        print(_c("\n  ✓  No issues found — clean file!\n", Fore.GREEN + Style.BRIGHT))


def _print_score_bar(label: str, score: float):
    filled = int(round(score))
    bar    = "█" * filled + "░" * (10 - filled)
    if score >= 8:
        color = Fore.GREEN
    elif score >= 5:
        color = Fore.YELLOW
    else:
        color = Fore.RED
    print(_c(f"  {label}  [{bar}] {score:4.1f}/10", color))


def print_global_summary(results: list):
    """Print aggregated summary across all scanned files."""
    valid = [r for r in results if "error" not in r]
    if not valid:
        print(_c("\n  No valid files were scanned.\n", Fore.RED))
        return

    total_findings = sum(r["total_findings"] for r in valid)
    avg_eff = sum(r["efficiency_score"] for r in valid) / len(valid)
    avg_eth = sum(r["ethical_score"]    for r in valid) / len(valid)
    total_lines = sum(r["total_lines"] for r in valid)

    criticals = sum(r["summary"].get("CRITICAL", 0) for r in valid)
    highs     = sum(r["summary"].get("HIGH", 0)     for r in valid)
    mediums   = sum(r["summary"].get("MEDIUM", 0)   for r in valid)
    lows      = sum(r["summary"].get("LOW", 0)       for r in valid)

    print(DIVIDER)
    print(_c("\n  ╔══════════════════════════════════════╗", Fore.CYAN + Style.BRIGHT))
    print(_c("  ║        GLOBAL SCAN SUMMARY           ║", Fore.CYAN + Style.BRIGHT))
    print(_c("  ╚══════════════════════════════════════╝\n", Fore.CYAN + Style.BRIGHT))

    print(_c(f"  Files Scanned    : {len(valid)}", Fore.WHITE))
    print(_c(f"  Total Lines      : {total_lines}", Fore.WHITE))
    print(_c(f"  Total Findings   : {total_findings}", Fore.YELLOW + Style.BRIGHT))
    print()
    _print_score_bar("Avg Efficiency   ", round(avg_eff, 1))
    _print_score_bar("Avg Ethical Safety", round(avg_eth, 1))
    print()

    breakdown = [
        (_c(f"  CRITICAL : {criticals}", SEV_COLOR["CRITICAL"])),
        (_c(f"  HIGH     : {highs}",     SEV_COLOR["HIGH"])),
        (_c(f"  MEDIUM   : {mediums}",   SEV_COLOR["MEDIUM"])),
        (_c(f"  LOW      : {lows}",      SEV_COLOR["LOW"])),
    ]
    for line in breakdown:
        print(line)

    # Engineering advice
    print()
    if avg_eff < 5:
        print(_c("  ⚠  Efficiency Alert: Multiple performance patterns detected.", Fore.RED))
        print(_c("     Review nested loops and resource management.", Fore.WHITE))
    if avg_eth < 5:
        print(_c("  ⚠  Ethics Alert: Sensitive data or security issues found.", Fore.RED))
        print(_c("     Audit PII handling and authentication logic.", Fore.WHITE))
    if avg_eff >= 8 and avg_eth >= 8:
        print(_c("  ✓  Excellent code health! Maintain these standards.", Fore.GREEN + Style.BRIGHT))
    print()


# ─── JSON Report ─────────────────────────────────────────────────────────────
def save_json_report(results: list, output_path: str):
    report = {
        "tool":       "SafeGuard-Code Profiler",
        "version":    "1.0.0",
        "timestamp":  datetime.now().isoformat(),
        "results":    results,
        "aggregate":  _aggregate(results),
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(_c(f"\n  📝 JSON report saved → {output_path}", Fore.GREEN))


# ─── HTML Report ─────────────────────────────────────────────────────────────
def save_html_report(results: list, output_path: str):
    agg  = _aggregate(results)
    rows = ""
    for r in results:
        if "error" in r:
            continue
        for f in r["findings"]:
            sev_class = f["severity"].lower()
            rows += f"""
            <tr class="sev-{sev_class}">
                <td>{r['filepath']}</td>
                <td class="sev-badge {sev_class}">{f['severity']}</td>
                <td>{f['rule_id']}</td>
                <td>{f['category'].capitalize()}</td>
                <td>Line {f['line']}</td>
                <td><code>{_esc(f['snippet'])}</code></td>
                <td>{_esc(f['message'])}</td>
            </tr>"""

    file_cards = ""
    for r in results:
        if "error" in r: continue
        eff_pct = r['efficiency_score'] * 10
        eth_pct = r['ethical_score']    * 10
        eff_cls = "good" if r['efficiency_score'] >= 8 else ("warn" if r['efficiency_score'] >= 5 else "bad")
        eth_cls = "good" if r['ethical_score']    >= 8 else ("warn" if r['ethical_score']    >= 5 else "bad")
        file_cards += f"""
        <div class="file-card">
            <div class="file-name">{r['filepath']}</div>
            <div class="lang-tag">{r['language'].upper()}</div>
            <div class="score-row">
                <span>Efficiency</span>
                <div class="bar-bg"><div class="bar-fill {eff_cls}" style="width:{eff_pct}%"></div></div>
                <span class="score-num {eff_cls}">{r['efficiency_score']}</span>
            </div>
            <div class="score-row">
                <span>Ethics</span>
                <div class="bar-bg"><div class="bar-fill {eth_cls}" style="width:{eth_pct}%"></div></div>
                <span class="score-num {eth_cls}">{r['ethical_score']}</span>
            </div>
            <div class="finding-count">{r['total_findings']} finding(s)</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeGuard-Code Profiler Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@400;500;600&display=swap');
  :root {{
    --bg: #0d0f14; --card: #13161d; --border: #1e2433;
    --text: #c9d1d9; --muted: #6e7681; --accent: #58a6ff;
    --critical: #ff4d4d; --high: #ffa500; --medium: #58a6ff; --low: #7ee787;
    --good: #7ee787; --warn: #ffa500; --bad: #ff4d4d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; padding: 2rem; line-height: 1.6; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .logo {{ font-family: 'JetBrains Mono', monospace; font-size: 1.8rem; font-weight: 800; color: var(--accent); letter-spacing: -1px; }}
  .logo span {{ color: var(--text); }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-num {{ font-family: 'JetBrains Mono', monospace; font-size: 2rem; font-weight: 800; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .files-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .file-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
  .file-name {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: var(--accent); word-break: break-all; margin-bottom: 0.4rem; }}
  .lang-tag {{ display: inline-block; font-size: 0.7rem; background: var(--border); border-radius: 4px; padding: 2px 8px; margin-bottom: 0.8rem; }}
  .score-row {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; font-size: 0.8rem; }}
  .score-row > span:first-child {{ width: 70px; color: var(--muted); }}
  .bar-bg {{ flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 3px; transition: width 0.5s; }}
  .bar-fill.good {{ background: var(--good); }}
  .bar-fill.warn {{ background: var(--warn); }}
  .bar-fill.bad  {{ background: var(--bad); }}
  .score-num {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; font-weight: 600; width: 32px; text-align: right; }}
  .score-num.good {{ color: var(--good); }} .score-num.warn {{ color: var(--warn); }} .score-num.bad {{ color: var(--bad); }}
  .finding-count {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.5rem; }}
  h2 {{ font-family: 'JetBrains Mono', monospace; font-size: 1rem; color: var(--accent); margin-bottom: 1rem; letter-spacing: 1px; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; background: var(--card); border-radius: 8px; overflow: hidden; }}
  th {{ background: var(--border); padding: 0.7rem 0.8rem; text-align: left; font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; background: rgba(255,255,255,0.05); padding: 2px 5px; border-radius: 3px; }}
  .sev-badge {{ font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; font-weight: 600; padding: 2px 7px; border-radius: 4px; }}
  .sev-badge.critical {{ color: var(--critical); background: rgba(255,77,77,0.1); }}
  .sev-badge.high {{ color: var(--high); background: rgba(255,165,0,0.1); }}
  .sev-badge.medium {{ color: var(--medium); background: rgba(88,166,255,0.1); }}
  .sev-badge.low {{ color: var(--low); background: rgba(126,231,135,0.1); }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 0.8rem; }}
</style>
</head>
<body>
<header>
  <div class="logo">SafeGuard<span>-Code Profiler</span></div>
  <div class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Files: {agg['total_files']} &nbsp;|&nbsp; Findings: {agg['total_findings']}</div>
</header>

<div class="stats-grid">
  <div class="stat-card"><div class="stat-num" style="color:var(--bad)">{agg['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--warn)">{agg['high']}</div><div class="stat-label">High</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--medium)">{agg['medium']}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--good)">{agg['low']}</div><div class="stat-label">Low</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--accent)">{agg['avg_efficiency']}</div><div class="stat-label">Avg Efficiency</div></div>
  <div class="stat-card"><div class="stat-num" style="color:var(--accent)">{agg['avg_ethics']}</div><div class="stat-label">Avg Ethics</div></div>
</div>

<h2>📄 File Scores</h2>
<div class="files-grid">{file_cards}</div>

<h2>🔍 All Findings</h2>
<table>
  <thead><tr><th>File</th><th>Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Code Snippet</th><th>Message</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="7" style="text-align:center;color:var(--good)">✓ No issues found</td></tr>'}</tbody>
</table>

<footer>SafeGuard-Code Profiler v1.0.0 &nbsp;·&nbsp; Bridging hardware awareness with software ethics.</footer>
</body>
</html>"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(_c(f"  🌐 HTML report saved → {output_path}", Fore.GREEN))


def _aggregate(results: list) -> dict:
    valid = [r for r in results if "error" not in r]
    if not valid:
        return {"total_files": 0, "total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                "avg_efficiency": 0, "avg_ethics": 0}
    return {
        "total_files":      len(valid),
        "total_findings":   sum(r["total_findings"] for r in valid),
        "critical":         sum(r["summary"].get("CRITICAL", 0) for r in valid),
        "high":             sum(r["summary"].get("HIGH", 0)     for r in valid),
        "medium":           sum(r["summary"].get("MEDIUM", 0)   for r in valid),
        "low":              sum(r["summary"].get("LOW", 0)       for r in valid),
        "avg_efficiency":   round(sum(r["efficiency_score"] for r in valid) / len(valid), 1),
        "avg_ethics":       round(sum(r["ethical_score"]    for r in valid) / len(valid), 1),
    }


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
