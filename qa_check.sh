#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[1/3] Python syntax"
python3 -m py_compile core/lookup.py core/ip_lookup.py scripts/run_report.py

echo "[2/3] Shell syntax"
for f in core/*.sh; do
  [[ -f "$f" ]] || continue
  bash -n "$f"
  echo "  OK  $f"
done

echo "[3/3] Pytest"
if command -v pytest >/dev/null 2>&1; then
  PYTHONPATH=. pytest -q
else
  echo "pytest not installed; skipping tests"
fi

echo "QA checks complete."
