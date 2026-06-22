.PHONY: sign verify serve demo test lint

CARD ?= cards/ellingson-agent-card.json
IDENTITY ?= https://ellingson-security.example/local-dev
OUT ?= build/signed-card.json

sign:
	@mkdir -p $(dir $(OUT))
	uv run ellingson-card sign --in $(CARD) --out $(OUT) --identity "$(IDENTITY)"

# Identity pinning is always on. --no-require-rekor is used for the local
# ephemeral signature, which is not logged to Rekor; the CI keyless card is
# verified with Rekor inclusion required.
verify:
	uv run ellingson-card verify --in $(OUT) --identity "$(IDENTITY)" --no-require-rekor

serve:
	uv run ellingson-card serve --card $(OUT)

demo:
	./scripts/demo.sh

test:
	uv run pytest -q

lint:
	uv run ruff check . && uv run ruff format --check . && uv run ty check
