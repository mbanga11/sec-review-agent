"""
Tools the agent can call. Every tool only touches REPO_ROOT.

File tools: list_files, read_file
Scanner tools: run_semgrep, run_osv_scanner, run_gitleaks

Scanner output is trimmed and deduplicated before it goes to the LLM,
because raw output is far too big (osv alone returned 201 vulns on NodeGoat).
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT: Path = Path(".").resolve()

MAX_FILE_CHARS = 8000   # trim big files so we don't blow the context window
MAX_LIST = 300          # max files returned by list_files
MAX_FINDINGS = 25       # max scanner findings sent to the model
SCAN_TIMEOUT = 300      # seconds before a scanner is killed
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor"}

_cache = {}  # scanner results for this run, so the agent can't trigger rescans


def set_repo_root(path) -> None:
    global REPO_ROOT
    REPO_ROOT = Path(path).resolve()
    _cache.clear()


def safe_path(rel_path: str) -> Path:
    """Resolve a path and refuse anything that escapes the repo (blocks ../ tricks)."""
    p = (REPO_ROOT / rel_path).resolve()
    if p != REPO_ROOT and REPO_ROOT not in p.parents:
        raise ValueError(f"Access denied: {rel_path} is outside the repo")
    return p


# ---------- File tools ----------
def list_files(path: str = ".") -> str:
    base = safe_path(path)
    if not base.is_dir():
        return f"Not a directory: {path}"
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            out.append(str((Path(dirpath) / name).relative_to(REPO_ROOT)))
            if len(out) >= MAX_LIST:
                return "\n".join(out) + "\n...(truncated)"
    return "\n".join(out) or "(no files)"


def read_file(path: str, start_line: int = 1, end_line: int = 0) -> str:
    p = safe_path(path)
    if not p.is_file():
        return f"Not a file: {path}"
    if p.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".crt"} or p.name.startswith(".env"):
        return f"Blocked: {path} looks like a secret or key file. Never send its contents to the LLM. Report it as a finding instead."
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, int(start_line))
    end = int(end_line) if end_line else len(lines)
    numbered = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, min(end, len(lines)) + 1))
    if len(numbered) > MAX_FILE_CHARS:
        numbered = numbered[:MAX_FILE_CHARS] + "\n...(truncated, use start_line/end_line)"
    return numbered or "(no lines in that range)"


# ---------- Scanner helpers ----------
def _run(cmd: list, ok_codes=(0, 1)) -> str:
    """Run a scanner with a fixed argument list. Never shell=True."""
    try:
        r = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except FileNotFoundError:
        raise RuntimeError(f"{cmd[0]} is not installed")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{cmd[0]} timed out after {SCAN_TIMEOUT}s")
    if r.returncode not in ok_codes:
        raise RuntimeError(f"{cmd[0]} failed (exit {r.returncode}): {r.stderr[-300:]}")
    return r.stdout


def _summary(tool: str, total: int, findings: list) -> str:
    return json.dumps({
        "tool": tool,
        "total_found": total,
        "shown": len(findings[:MAX_FINDINGS]),
        "findings": findings[:MAX_FINDINGS],
        "note": "Scanner hits can be false positives. Read the code before deciding.",
    }, indent=1)


# ---------- Scanner tools ----------
SEMGREP_SEVERITY = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def run_semgrep() -> str:
    if "semgrep" in _cache:
        return _cache["semgrep"]
    config = os.getenv("SEMGREP_CONFIG", "p/owasp-top-ten")
    out = _run(["semgrep", "scan", "--config", config, "--metrics=off", "--json", "--quiet", "."])
    results = json.loads(out).get("results", [])

    # Dedupe: one finding per file+line (6 cookie rules on server.js:78 become 1)
    merged = {}
    for r in results:
        key = (r["path"], r["start"]["line"])
        extra = r.get("extra", {})
        cwe = extra.get("metadata", {}).get("cwe") or []
        rule = r["check_id"].split(".")[-1]
        item = {
            "file": r["path"],
            "line": r["start"]["line"],
            "rules": [rule],
            "severity": extra.get("severity", "INFO"),
            "cwe": cwe[0] if isinstance(cwe, list) and cwe else cwe or None,
            "message": (extra.get("message") or "")[:200],
        }
        if key not in merged:
            merged[key] = item
            continue
        old = merged[key]
        old["rules"].append(rule)
        # keep the most severe rule's details, and any CWE we can find
        if SEMGREP_SEVERITY.get(item["severity"], 3) < SEMGREP_SEVERITY.get(old["severity"], 3):
            old.update(severity=item["severity"], message=item["message"], cwe=item["cwe"] or old["cwe"])
        old["cwe"] = old["cwe"] or item["cwe"]
    findings = sorted(merged.values(), key=lambda f: SEMGREP_SEVERITY.get(f["severity"], 3))
    _cache["semgrep"] = _summary("semgrep", len(results), findings)
    return _cache["semgrep"]


def _max_severity(pkg: dict) -> float:
    scores = []
    for g in pkg.get("groups", []):
        try:
            scores.append(float(g.get("max_severity") or 0))
        except ValueError:
            pass
    return max(scores, default=0.0)


def run_osv_scanner() -> str:
    if "osv" in _cache:
        return _cache["osv"]
    # exit 1 just means vulns were found
    out = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", "."])
    data = json.loads(out) if out.strip() else {}

    total = 0
    findings = []
    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            vulns = pkg.get("vulnerabilities", [])
            total += len(vulns)
            findings.append({
                "package": pkg["package"]["name"],
                "version": pkg["package"].get("version"),
                "vuln_count": len(vulns),
                "max_cvss": _max_severity(pkg),
                "ids": [v["id"] for v in vulns][:5],
                "lockfile": res.get("source", {}).get("path", "").replace(str(REPO_ROOT) + "/", ""),
            })
    findings.sort(key=lambda f: (f["max_cvss"], f["vuln_count"]), reverse=True)
    _cache["osv"] = _summary("osv-scanner", total, findings)
    return _cache["osv"]


def run_gitleaks() -> str:
    if "gitleaks" in _cache:
        return _cache["gitleaks"]
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        # --redact keeps secret values out of the report (and out of the LLM)
        _run(["gitleaks", "git", ".", "--redact", "--no-banner",
              "--report-format", "json", "--report-path", str(report), "--exit-code", "0"])
        leaks = json.loads(report.read_text() or "[]") if report.exists() else []

    # Dedupe: same secret in the same file across several commits counts once
    merged = {}
    for l in leaks:
        key = (l.get("File"), l.get("RuleID"))
        if key in merged:
            merged[key]["commits"] += 1
            continue
        merged[key] = {
            "file": l.get("File"),
            "line": l.get("StartLine"),
            "rule": l.get("RuleID"),
            "description": l.get("Description"),
            "first_commit": (l.get("Commit") or "")[:7],
            "commits": 1,
        }
    _cache["gitleaks"] = _summary("gitleaks", len(leaks), list(merged.values()))
    return _cache["gitleaks"]


# ---------- Registry ----------
# Allowlist: the model can only call what's in here.
TOOL_FUNCS = {
    "list_files": list_files,
    "read_file": read_file,
    "run_semgrep": run_semgrep,
    "run_osv_scanner": run_osv_scanner,
    "run_gitleaks": run_gitleaks,
}


def _tool(name, description, properties=None, required=None):
    params = {"type": "object", "properties": properties or {}}
    if required:
        params["required"] = required
    return {"type": "function", "function": {"name": name, "description": description, "parameters": params}}


TOOLS = [
    _tool("list_files", "List files in the repo (recursive). Skips .git, node_modules, etc.",
          {"path": {"type": "string", "description": "Directory relative to repo root. Default '.'"}}),
    _tool("read_file", "Read a file with line numbers. Use start_line/end_line to read just the code around a finding.",
          {"path": {"type": "string", "description": "File path relative to repo root."},
           "start_line": {"type": "integer", "description": "First line to read (default 1)."},
           "end_line": {"type": "integer", "description": "Last line to read (default end of file)."}},
          ["path"]),
    _tool("run_semgrep", "Static analysis (SAST) for vulnerable code patterns. Returns deduplicated findings with file, line, rule, CWE."),
    _tool("run_osv_scanner", "Scan dependency lockfiles for packages with known CVEs. Returns packages sorted by severity."),
    _tool("run_gitleaks", "Scan the full git history for hardcoded secrets. Values are redacted."),
]


def run_tool(name: str, raw_args: str) -> str:
    if name not in TOOL_FUNCS:
        return f"Error: unknown tool '{name}'"
    try:
        args = json.loads(raw_args or "{}")
        return TOOL_FUNCS[name](**args)
    except Exception as e:  # return errors to the model instead of crashing
        return f"Error: {e}"



# ---------- Phase 4: triage ----------
# The agent records a structured verdict for every candidate issue.
# These become findings.json, which the compliance mapping and report build on.

FINDINGS = []
VERDICTS = {"true_positive", "false_positive", "needs_review"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SOURCES = {"semgrep", "osv-scanner", "gitleaks", "manual"}


def record_finding(title, file, line, verdict, severity, source, reasoning, cwe="", fix="") -> str:
    verdict, severity, source = verdict.lower(), severity.lower(), source.lower()
    if verdict not in VERDICTS:
        return f"Error: verdict must be one of {sorted(VERDICTS)}"
    if severity not in SEVERITIES:
        return f"Error: severity must be one of {SEVERITIES}"
    if source not in SOURCES:
        return f"Error: source must be one of {sorted(SOURCES)}"
    # The file must really exist, so the model can't invent locations.
    # Gitleaks hits can be in files deleted from the current tree, so they skip this check.
    if source != "gitleaks" and not safe_path(file).is_file():
        return f"Error: {file} does not exist. Check the path and record again."
    line = int(line or 0)
    for f in FINDINGS:
        if f["file"] == file and f["line"] == line and f["title"].lower() == title.lower():
            return f"Already recorded as #{f['id']}. Skipped duplicate."
    FINDINGS.append({
        "id": len(FINDINGS) + 1,
        "title": title, "file": file, "line": line, "cwe": cwe,
        "severity": severity, "verdict": verdict, "source": source,
        "reasoning": reasoning, "fix": fix,
    })
    return f"Recorded #{len(FINDINGS)} ({verdict})."


def save_findings(path, meta: dict) -> dict:
    counts = {v: sum(f["verdict"] == v for f in FINDINGS) for v in sorted(VERDICTS)}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({**meta, "counts": counts, "findings": FINDINGS}, indent=2))
    return counts


TOOL_FUNCS["record_finding"] = record_finding
TOOLS.append(_tool(
    "record_finding",
    "Record your verdict on ONE candidate issue. Call it once per issue, including false positives.",
    {"title": {"type": "string", "description": "Short name, e.g. 'NoSQL injection via $where'."},
     "file": {"type": "string", "description": "File path relative to repo root."},
     "line": {"type": "integer", "description": "Line number (0 if not line-specific)."},
     "verdict": {"type": "string", "enum": sorted(VERDICTS)},
     "severity": {"type": "string", "enum": SEVERITIES},
     "source": {"type": "string", "enum": sorted(SOURCES)},
     "cwe": {"type": "string", "description": "e.g. 'CWE-943'. Empty if unknown."},
     "reasoning": {"type": "string", "description": "Why this verdict. For false positives, why it is not a real risk."},
     "fix": {"type": "string", "description": "How to fix it. Empty for false positives."}},
    ["title", "file", "line", "verdict", "severity", "source", "reasoning"],
))


# ---------- Phase 4b: self-review ----------
# Lets the agent correct its own verdicts during the review pass.
VERDICTS.add("duplicate")
for t in TOOLS:
    if t["function"]["name"] == "record_finding":
        t["function"]["parameters"]["properties"]["verdict"]["enum"] = sorted(VERDICTS)


def update_finding(id, verdict, reasoning, severity="") -> str:
    verdict = verdict.lower()
    if verdict not in VERDICTS:
        return f"Error: verdict must be one of {sorted(VERDICTS)}"
    for f in FINDINGS:
        if f["id"] == int(id):
            f["verdict"], f["reasoning"] = verdict, reasoning
            if severity:
                if severity.lower() not in SEVERITIES:
                    return f"Error: severity must be one of {SEVERITIES}"
                f["severity"] = severity.lower()
            return f"Updated #{f['id']} -> {verdict}."
    return f"Error: no finding #{id}"


def findings_table() -> str:
    rows = [f"#{f['id']} | {f['verdict']} | {f['severity']} | {f['source']} | {f['file']}:{f['line']} | {f['title']}"
            for f in FINDINGS]
    return "\n".join(rows) or "(none recorded)"


TOOL_FUNCS["update_finding"] = update_finding
TOOLS.append(_tool(
    "update_finding",
    "Change the verdict (and optionally severity) of a finding you already recorded. Use 'duplicate' for repeats.",
    {"id": {"type": "integer", "description": "The finding number, e.g. 3 for #3."},
     "verdict": {"type": "string", "enum": sorted(VERDICTS)},
     "reasoning": {"type": "string", "description": "Why you changed it, e.g. 'duplicate of #1' or 'tutorial page link, not reachable by users'."},
     "severity": {"type": "string", "enum": SEVERITIES}},
    ["id", "verdict", "reasoning"],
))