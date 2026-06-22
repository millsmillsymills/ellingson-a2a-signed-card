#!/usr/bin/env bash
# Hermetic, offline end-to-end demo: sign -> verify -> tamper -> reject.
# Local signing uses an ephemeral key with no Rekor entry, so verification runs
# with --no-require-rekor; the CI keyless workflow produces the Rekor-logged card.
set -euo pipefail

IDENTITY="https://ellingson-security.example/local-dev"
CARD="cards/ellingson-agent-card.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUT="$WORK/signed-card.json"

echo "== sign =="
uv run ellingson-card sign --in "$CARD" --out "$OUT" --identity "$IDENTITY"

echo "== verify (valid card) =="
uv run ellingson-card verify --in "$OUT" --identity "$IDENTITY" --no-require-rekor

echo "== tamper one field and re-verify (must be rejected) =="
python3 -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['name']='tampered'; json.dump(d, open(p,'w'))" "$OUT"
if uv run ellingson-card verify --in "$OUT" --identity "$IDENTITY" --no-require-rekor; then
  echo "ERROR: tampered card verified — control failed" >&2
  exit 1
fi
echo "tampered card correctly rejected"
