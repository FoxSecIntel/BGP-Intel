#!/bin/bash
set -euo pipefail

__r17q_blob="wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="
if [[ "${1:-}" == "m" || "${1:-}" == "-m" ]]; then
  echo "$__r17q_blob" | base64 --decode
  exit 0
fi


cd "$(dirname "$0")"

echo "[1/3] Python syntax"
python3 -m py_compile core/lookup.py core/ip_lookup.py scripts/run_report.py scripts/bgp_hijack_check.py scripts/rpki_check.py

echo "[2/3] Shell syntax"
for f in core/archive/*.sh; do
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
