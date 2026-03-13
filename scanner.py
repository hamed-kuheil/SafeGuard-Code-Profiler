"""
scanner.py — SafeGuard-Code Profiler
Core scanning engine: reads source files, applies regex rules,
computes Resource Efficiency Score and Ethical Safety Score.
"""

import re
import os
from pathlib import Path
from rules import (
    get_rules_for_language,
    EFFICIENCY_RULES,
    SAFETY_RULES,
    ETHICAL_RULES,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
)

# ─── Language Detection ───────────────────────────────────────────────────────
EXTENSION_MAP = {
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc":  "cpp",
    ".c":   "cpp",
    ".h":   "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".py":   "python",
}

SEVERITY_WEIGHT = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}
SEVERITY_COLOR_TAG = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO"}


def detect_language(filepath: str) -> str | None:
    ext = Path(filepath).suffix.lower()
    return EXTENSION_MAP.get(ext)


def _find_line_number(content: str, match_start: int) -> int:
    return content[:match_start].count("\n") + 1


def scan_file(filepath: str) -> dict:
    """
    Scan a single source file and return a structured result dict.
    """
    language = detect_language(filepath)
    if not language:
        return {"error": f"Unsupported file type: {filepath}"}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return {"error": str(e)}

    lines = content.splitlines()
    findings = []
    rules = get_rules_for_language(language)

    for rule in rules:
        pattern = rule["pattern"]
        flags = rule.get("flags", 0) | re.MULTILINE

        try:
            for match in re.finditer(pattern, content, flags):
                line_num = _find_line_number(content, match.start())
                snippet = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                findings.append({
                    "rule_id":   rule["id"],
                    "name":      rule["name"],
                    "severity":  rule["severity"],
                    "category":  rule["category"],
                    "message":   rule["message"],
                    "line":      line_num,
                    "snippet":   snippet[:120],
                })
        except re.error:
            pass  # Gracefully skip malformed patterns

    # ── Dedup: keep first occurrence per rule per line ─────────────────────
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["rule_id"], f["line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    unique_findings.sort(key=lambda x: (SEVERITY_WEIGHT.get(x["severity"], 0)), reverse=True)

    efficiency_score = _compute_efficiency_score(unique_findings, lines)
    ethical_score    = _compute_ethical_score(unique_findings)

    return {
        "filepath":         filepath,
        "language":         language,
        "total_lines":      len(lines),
        "findings":         unique_findings,
        "total_findings":   len(unique_findings),
        "efficiency_score": efficiency_score,
        "ethical_score":    ethical_score,
        "summary":          _build_summary(unique_findings),
    }


def _compute_efficiency_score(findings: list, lines: list) -> float:
    """
    Compute Resource Efficiency Score (1–10).
    Start at 10, deduct based on efficiency findings weighted by severity.
    """
    score = 10.0
    eff_findings = [f for f in findings if f["category"] == "efficiency"]
    for f in eff_findings:
        deduct = {CRITICAL: 2.5, HIGH: 1.5, MEDIUM: 0.8, LOW: 0.3, INFO: 0.1}
        score -= deduct.get(f["severity"], 0.5)
    return round(max(1.0, min(10.0, score)), 1)


def _compute_ethical_score(findings: list) -> float:
    """
    Compute Ethical Safety Score (1–10).
    Combines security and ethics categories.
    """
    score = 10.0
    concern_findings = [f for f in findings if f["category"] in ("security", "ethics")]
    for f in concern_findings:
        deduct = {CRITICAL: 2.5, HIGH: 1.8, MEDIUM: 1.0, LOW: 0.4, INFO: 0.1}
        score -= deduct.get(f["severity"], 0.5)
    return round(max(1.0, min(10.0, score)), 1)


def _build_summary(findings: list) -> dict:
    summary = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
               "efficiency": 0, "security": 0, "ethics": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        summary[f["category"]] = summary.get(f["category"], 0) + 1
    return summary


def scan_directory(dirpath: str, recursive: bool = True) -> list:
    """
    Scan all supported files in a directory.
    """
    results = []
    path = Path(dirpath)
    pattern = "**/*" if recursive else "*"
    for fpath in path.glob(pattern):
        if fpath.is_file() and fpath.suffix.lower() in EXTENSION_MAP:
            results.append(scan_file(str(fpath)))
    return results
