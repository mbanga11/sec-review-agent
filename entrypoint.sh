#!/bin/sh
# Full pipeline: agent review -> compliance mapping -> report.
set -e
TASK="${TASK:-Do a full secure code review. Use the scanners, verify each finding, and record a verdict for every candidate.}"

if [ ! -d /target ]; then
  echo "Mount the repo to scan at /target (read-only), e.g. -v /path/to/repo:/target:ro"
  exit 1
fi

python agent.py /target "$TASK"
python compliance.py "$REPORTS_DIR/findings.json"
python report.py "$REPORTS_DIR/findings.json" "$REPORTS_DIR/report.md"
echo "Done. Report: out/reports/report.md  Audit log: out/logs/run.jsonl"
