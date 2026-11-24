"""
Phase 5: compliance mapping. No LLM involved.

Reads reports/findings.json, looks up each finding's CWE in data/cwe_controls.json,
and writes the matching OWASP Top 10:2025, NIST 800-53, and SOC 2 controls back
into each finding. Deterministic on purpose: an LLM would make up control IDs.

Usage:
    python compliance.py [reports/findings.json]
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

TABLE_PATH = Path(__file__).parent / "data" / "cwe_controls.json"
COUNTED = {"true_positive", "needs_review"}  # dismissed findings don't count against controls


def load_table() -> dict:
    return json.loads(TABLE_PATH.read_text())


def cwes_for(finding: dict, table: dict) -> list:
    """Pull every CWE-<n> out of the finding. Fall back to a default for scanners that don't give one."""
    found = re.findall(r"CWE-(\d+)", f"{finding.get('cwe', '')}", re.IGNORECASE)
    cwes = list(dict.fromkeys(f"CWE-{n}" for n in found))  # dedupe, keep order
    if not cwes:
        defaults = table["_source_defaults"]
        source = finding.get("source", "")
        title = finding.get("title", "").lower()
        if source == "gitleaks" and ("private" in title or "key" in finding.get("file", "").lower()):
            cwes = [defaults["gitleaks:private-key"]]
        elif source in defaults:
            cwes = [defaults[source]]
    return cwes


def map_finding(finding: dict, table: dict) -> dict:
    cwes = cwes_for(finding, table)
    owasp, nist, soc2, unmapped = [], [], [], []
    for cwe in cwes:
        entry = table.get(cwe)
        if not entry:
            unmapped.append(cwe)
            continue
        owasp.append(entry["owasp"])
        nist += entry["nist"]
        soc2 += entry["soc2"]
    uniq = lambda xs: list(dict.fromkeys(xs))
    return {
        "cwes": cwes,
        "owasp": uniq(owasp),
        "nist_800_53": uniq(nist),
        "soc2": uniq(soc2),
        "unmapped_cwes": unmapped,
    }


def main(path: str) -> None:
    data = json.loads(Path(path).read_text())
    table = load_table()

    by_control = defaultdict(list)  # control -> finding ids (true positives / needs review only)
    unmapped = []
    for f in data["findings"]:
        f["controls"] = map_finding(f, table)
        if f["verdict"] in COUNTED:
            for c in f["controls"]["owasp"] + f["controls"]["nist_800_53"] + f["controls"]["soc2"]:
                by_control[c].append(f["id"])
            if not f["controls"]["cwes"] or f["controls"]["unmapped_cwes"]:
                unmapped.append(f)

    data["compliance"] = {
        "frameworks": ["OWASP Top 10:2025", "NIST SP 800-53 Rev. 5", "SOC 2 TSC 2017"],
        "controls_affected": {c: ids for c, ids in sorted(by_control.items())},
        "unmapped_finding_ids": [f["id"] for f in unmapped],
    }
    Path(path).write_text(json.dumps(data, indent=2))

    # ---------- Console summary ----------
    counted = [f for f in data["findings"] if f["verdict"] in COUNTED]
    print(f"Mapped {len(data['findings'])} findings ({len(counted)} counted: true positive or needs review)\n")
    def family(c):
        if re.match(r"[A-Z]{2}-\d", c):
            return "NIST 800-53"
        if re.match(r"(CC|A)\d\.\d", c):
            return "SOC 2"
        return "OWASP Top 10:2025"
    for label in ("OWASP Top 10:2025", "NIST 800-53", "SOC 2"):
        print(label)
        for c, ids in sorted(by_control.items()):
            if family(c) == label:
                print(f"  {c:<45} {len(ids)} finding(s)  #{', #'.join(map(str, ids))}")
        print()
    if unmapped:
        print("Not mapped (add these CWEs to data/cwe_controls.json):")
        for f in unmapped:
            print(f"  #{f['id']} {f['title']}  cwe={f.get('cwe') or '(none)'}")
    else:
        print("Every counted finding mapped to at least one control.")
    print(f"\nUpdated {path}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "reports/findings.json")
    