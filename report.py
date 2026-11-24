"""
Phase 6: turn reports/findings.json into a readable Markdown report. No LLM involved.

Usage:
    python report.py [reports/findings.json] [reports/report.md]
"""

import json
import sys
from collections import Counter
from pathlib import Path

import compliance

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
BLOCKED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".crt"}  # never print key material
LANG = {".js": "javascript", ".ts": "typescript", ".py": "python", ".html": "html",
        ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".java": "java", ".go": "go"}


def cell(text) -> str:
    """Make text safe for a Markdown table cell."""
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def location(f) -> str:
    return f"`{f['file']}:{f['line']}`" if f.get("line") else f"`{f['file']}`"


def snippet(target: Path, f: dict, context: int = 2) -> str:
    """A few lines of code around the finding, if the file still exists."""
    path = target / f["file"]
    line = int(f.get("line") or 0)
    # Never show code for secret findings: the snippet would print the secret gitleaks redacted
    if f.get("source") == "gitleaks" or line <= 0 or not path.is_file():
        return ""
    if path.suffix.lower() in BLOCKED_SUFFIXES or path.name.startswith(".env"):
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start, end = max(1, line - context), min(len(lines), line + context)
    if start > end:
        return ""
    body = "\n".join(f"{'>' if i == line else ' '} {i:>4} | {lines[i - 1][:160]}" for i in range(start, end + 1))
    return f"```{LANG.get(path.suffix.lower(), '')}\n{body}\n```"


def controls_line(f) -> str:
    c = f.get("controls", {})
    parts = []
    if c.get("owasp"):
        parts.append("OWASP " + ", ".join(c["owasp"]))
    if c.get("nist_800_53"):
        parts.append("NIST " + ", ".join(c["nist_800_53"]))
    if c.get("soc2"):
        parts.append("SOC 2 " + ", ".join(c["soc2"]))
    return "; ".join(parts) or "not mapped"


def finding_block(f, target: Path) -> list:
    out = [f"#### #{f['id']} {f['title']}",
           "",
           f"- **Severity:** {f['severity'].title()}",
           f"- **Location:** {location(f)}",
           f"- **Found by:** {f['source']}",
           f"- **CWE:** {', '.join(f.get('controls', {}).get('cwes', [])) or f.get('cwe') or 'unknown'}",
           f"- **Controls:** {controls_line(f)}",
           "",
           f"**Why it matters:** {f.get('reasoning', '').strip()}",
           ""]
    if f.get("fix"):
        out += [f"**Fix:** {f['fix'].strip()}", ""]
    code = snippet(target, f)
    if code:
        out += [code, ""]
    return out


def build(data: dict) -> str:
    target = Path(data.get("target", "."))
    findings = data["findings"]
    confirmed = sorted([f for f in findings if f["verdict"] == "true_positive"],
                       key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"]))
    review = [f for f in findings if f["verdict"] == "needs_review"]
    dismissed = [f for f in findings if f["verdict"] in ("false_positive", "duplicate")]
    sev = Counter(f["severity"] for f in confirmed)

    md = [f"# Security Review: {target.name}", ""]
    md += ["| | |", "|---|---|",
           f"| Target | `{target.name}` |",
           f"| Scanned | {data.get('scanned_at', 'unknown')} |",
           f"| Model | {data.get('model', 'unknown')} ({data.get('steps', '?')} agent steps) |",
           "| Scanners | Semgrep (SAST), osv-scanner (dependencies), gitleaks (secrets), plus LLM manual review |",
           f"| Run status | {data.get('status', 'unknown')} |", ""]
    if data.get("status", "complete") != "complete":
        md += ["> **Warning:** this run did not finish, so the report is incomplete.", ""]

    # ---------- Executive summary ----------
    md += ["## Executive summary", "",
           f"**{len(confirmed)} confirmed issues**, {len(review)} needing review, "
           f"{len(dismissed)} dismissed as false positives or duplicates.", "",
           "| Critical | High | Medium | Low | Info |", "|---|---|---|---|---|",
           "| " + " | ".join(str(sev.get(s, 0)) for s in SEVERITY_ORDER) + " |", ""]
    top = [f for f in confirmed if f["severity"] in ("critical", "high")][:6]
    if top:
        md += ["**Fix first:**", ""]
        md += [f"{i}. **{f['title']}** ({f['severity']}) in {location(f)}" for i, f in enumerate(top, 1)]
        md += [""]

    # ---------- Findings ----------
    md += ["## Confirmed findings", ""]
    for s in SEVERITY_ORDER:
        group = [f for f in confirmed if f["severity"] == s]
        if not group:
            continue
        md += [f"### {s.title()} ({len(group)})", ""]
        for f in group:
            md += finding_block(f, target)
    if not confirmed:
        md += ["None.", ""]

    if review:
        md += ["## Needs human review", ""]
        for f in review:
            md += finding_block(f, target)

    # ---------- Dismissed ----------
    md += ["## Dismissed", "",
           "Flagged by a scanner but judged not to be a real risk, or a repeat of another finding.", ""]
    if dismissed:
        md += ["| # | Location | Verdict | Reason |", "|---|---|---|---|"]
        md += [f"| {f['id']} | {location(f)} | {f['verdict'].replace('_', ' ')} | {cell(f.get('reasoning'))} |"
               for f in dismissed]
    else:
        md += ["None."]
    md += [""]

    # ---------- Compliance ----------
    affected = data.get("compliance", {}).get("controls_affected", {})
    md += ["## Compliance impact", "",
           "Each confirmed finding is mapped from its CWE to the controls below (see `data/cwe_controls.json`).", ""]
    for label, test in (("OWASP Top 10:2025", lambda c: c[:1] == "A" and ":" in c),
                        ("NIST SP 800-53 Rev. 5", lambda c: c[:2].isalpha() and c[2:3] == "-"),
                        ("SOC 2 Trust Services Criteria", lambda c: c[:2] == "CC" or (c[:1] == "A" and "." in c and ":" not in c))):
        rows = [(c, ids) for c, ids in affected.items() if test(c)]
        if rows:
            md += [f"### {label}", "", "| Control | Findings |", "|---|---|"]
            md += [f"| {cell(c)} | {', '.join('#' + str(i) for i in ids)} |"
                   for c, ids in sorted(rows, key=lambda r: (-len(r[1]), r[0]))]
            md += [""]

    # ---------- Methodology ----------
    md += ["## Methodology and limitations", "",
           "- Scanners ran first. An LLM agent then read the code around each hit, judged whether it was real, "
           "and reviewed key files by hand for logic bugs scanners miss (IDOR, injection through data flow).",
           "- A self-review pass made the agent recheck its own verdicts for false positives and duplicates before finishing.",
           "- Compliance mapping is deterministic (no LLM), so control IDs cannot be hallucinated. "
           "The mapping table was written by hand and should be verified before a real audit.",
           f"- Results depend on the model ({data.get('model', 'unknown')}). An LLM can miss issues or misjudge them, "
           "so treat this as a starting point for human review, not a final answer.",
           "- Secret values were redacted, and key files were never sent to the LLM.", ""]
    return "\n".join(md)


def main(src: str, dest: str) -> None:
    data = json.loads(Path(src).read_text())
    if any("controls" not in f for f in data["findings"]) or "compliance" not in data:
        print("Findings not mapped yet, running compliance.py first...\n")
        compliance.main(src)
        data = json.loads(Path(src).read_text())
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    Path(dest).write_text(build(data))
    confirmed = sum(f["verdict"] == "true_positive" for f in data["findings"])
    print(f"Wrote {dest}: {confirmed} confirmed of {len(data['findings'])} findings")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "reports/findings.json",
         sys.argv[2] if len(sys.argv) > 2 else "reports/report.md")