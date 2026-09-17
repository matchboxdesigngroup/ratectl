#!/usr/bin/env bash
# Run the whole suite: unit tests first (fast, no nginx), then integration.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '\033[1m=== Unit tests ===\033[0m\n'
python3 "$ROOT/tests/test_unit.py" 2>&1 | tail -5
unit=${PIPESTATUS[0]}

printf '\n\033[1m=== Integration tests ===\033[0m\n'
"$ROOT/tests/integration.sh"
integration=$?

printf '\n\033[1m=== Result ===\033[0m\n'
[ "$unit" -eq 0 ] && echo "unit:        pass" || echo "unit:        FAIL"
[ "$integration" -eq 0 ] && echo "integration: pass" || echo "integration: FAIL"
[ "$unit" -eq 0 ] && [ "$integration" -eq 0 ]
