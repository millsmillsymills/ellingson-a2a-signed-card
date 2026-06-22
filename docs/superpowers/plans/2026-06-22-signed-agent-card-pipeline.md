# Signed Agent Card Provenance Pipeline — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ellingson-a2a-signed-card`: serve a spec-valid v1.0 A2A Agent Card whose trust is bound to a DNSSEC/CT-hardened delivery channel, signed keyless in CI and verifiable end-to-end in minutes — emitting a **v1.0-spec-native `AgentCardSignature`**.

**Architecture:** A small Python package (`ellingson_card`) implements: RFC 8785 JCS canonicalization (excluding the `signatures` field), ES256 JWS signing producing a spec-native `AgentCardSignature` (`protected`/`signature`/`header`), and a fail-closed verifier (signature → identity pinning → Rekor inclusion → freshness). Local `make sign/verify/demo` run hermetically with an ephemeral key + self-signed cert; a GitHub Actions workflow does the real Sigstore keyless flow (Fulcio cert in `x5c`, Rekor log index in a custom unprotected header field). Card is served at `/.well-known/agent-card.json` via stdlib `http.server` with security headers. Delivery hardening (DNSSEC + CT) is documented and diagrammed against the real pattern (served locally per D-B2).

**Tech Stack:** Python 3.13 (uv), `a2a-sdk` (authoritative v1.0 card types), `rfc8785` (JCS), `cryptography` (ES256 + self-signed cert), `sigstore` (keyless CI path), stdlib `http.server`. Tooling: ruff, ty, pytest. CI: GitHub Actions with OIDC.

## Global Constraints

- **Phase-0 decision D-B1 = option (b):** implement spec-native JWS-over-JCS directly on `cryptography`/`sigstore`. `sigstore-a2a` (RedDotRocket) emits a non-spec wrapper (`{agentCard, verificationMaterial}`, `protocolVersion: "0.2.9"`, in-toto DSSE) — NOT the v1.0 `signatures[]`/`AgentCardSignature` shape. Do NOT depend on it.
- **D-B2:** serve locally; DNSSEC/CT described & diagrammed, not live-served. Leave a documented upgrade path.
- **Spec target:** A2A **v1.0.0** (verified 2026-06-22). Well-known path `/.well-known/agent-card.json`. `AgentCardSignature` = `{protected (req, b64url JWS header), signature (req, b64url detached-payload sig), header (opt object)}`. Canonical form = RFC 8785 JCS over the card **with `signatures` removed**. Alg: **ES256**.
- **No long-lived keys** in repo/CI. CI signing uses OIDC (`id-token: write`), SHA-pinned actions, least-privilege `permissions:`.
- **Verifier fails closed** with a **distinct, testable error** per case: missing signature, wrong identity, absent Rekor entry, expired card, missing well-known path, plaintext endpoint.
- **No novel crypto** (N4). **Honesty:** README states what's demonstrated vs production scale; any prototype dep disclosed; "early and informed," not "battle-tested." Org persona: **Ellingson Security Research**.
- Dep pins (exact `==`): `a2a-sdk==1.1.0`, `rfc8785==0.1.4`, `cryptography==49.0.0`, `sigstore==4.3.0`. Verify a2a-sdk exposes `AgentCard`/`AgentCardSignature` at scaffold time; if not, hand-roll a minimal pydantic model targeting v1.0 fields.
- Hard limits: ≤100 lines/function, complexity ≤8, ≤5 positional params, 100-char lines, absolute imports only.

---

### Task 1: Repo scaffold + tooling guardrails

**Files:** Create `pyproject.toml`, `.gitignore`, `.pre-commit-config.yaml`, `LICENSE` (Apache-2.0), `src/ellingson_card/__init__.py`, `tests/__init__.py`, `.github/workflows/ci.yml`.

**Produces:** installable package `ellingson_card`; `uv run pytest/ruff/ty` all green on an empty smoke test.

- [ ] Verify `a2a-sdk==1.1.0` exposes `AgentCard` and `AgentCardSignature` (`uv run python -c "from a2a.types import AgentCard, AgentCardSignature"`); record result in a comment in `card.py` (Task 2). If absent, switch Task 2 to a hand-rolled pydantic model.
- [ ] Write `pyproject.toml` (uv_build, deps pinned `==`, `[tool.ruff]`, `[tool.ty.rules]` strict, pytest config).
- [ ] Write a smoke test `tests/test_smoke.py` asserting `import ellingson_card`. Run `uv run pytest -q` → PASS.
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run ty check` → all clean.
- [ ] CI workflow: matrix on 3.13, runs ruff/ty/pytest, SHA-pinned `actions/checkout` + `astral-sh/setup-uv`, `permissions: contents: read`, `persist-credentials: false`.
- [ ] Commit: `chore: scaffold ellingson-a2a-signed-card package and CI`.

### Task 2: Agent Card model + the canonical Ellingson card

**Files:** Create `src/ellingson_card/card.py`, `cards/ellingson-agent-card.json`; Test `tests/test_card.py`.

**Interfaces — Produces:**
- `load_card(path: Path) -> AgentCard` — parse + validate against v1.0 model; raises `CardError` on invalid.
- `card_for_signing(card: AgentCard) -> dict` — model dump with `signatures` removed and `None` fields excluded.

- [ ] **Test:** `cards/ellingson-agent-card.json` loads, has `protocolVersion == "1.0"`, `securitySchemes` present, `supportedInterfaces[0].protocolBinding`, and skills. `card_for_signing` output has no `signatures` key.
- [ ] Author `cards/ellingson-agent-card.json`: v1.0 shapes — `supportedInterfaces[]` (not `preferredTransport`), `securitySchemes` (OAuth2 Authorization Code + `pkce_required: true`), realistic Ellingson skills, `https://` url.
- [ ] Implement `card.py` using `a2a.types.AgentCard`; `card_for_signing` = `card.model_dump(by_alias=True, exclude_none=True, mode="json")` then `pop("signatures", None)`.
- [ ] Run tests → PASS. Commit: `feat: add v1.0 Ellingson agent card and loader`.

### Task 3: RFC 8785 JCS canonicalization

**Files:** Create `src/ellingson_card/canonical.py`; Test `tests/test_canonical.py`.

**Interfaces — Produces:** `canonicalize(card: AgentCard) -> bytes` — JCS bytes of the signing view (signatures excluded). Consumes `card_for_signing`.

- [ ] **Test:** canonical bytes are deterministic across two calls; key order is lexicographic; re-canonicalizing a card with a `signatures` field added yields identical bytes (proves exclusion); known small dict matches a hand-computed JCS string.
- [ ] Implement with `rfc8785.dumps(card_for_signing(card))`.
- [ ] Run tests → PASS. Commit: `feat: JCS canonicalization excluding signatures field`.

### Task 4: ES256 keypair + self-signed cert helper (local/hermetic path)

**Files:** Create `src/ellingson_card/keys.py`; Test `tests/test_keys.py`.

**Interfaces — Produces:**
- `generate_signing_material(identity: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]` — P-256 key + self-signed cert with `identity` as a URI SAN.
- `cert_to_x5c(cert: x509.Certificate) -> list[str]` — base64 DER chain for the JWS `x5c` header.
- `identity_from_cert(cert: x509.Certificate) -> str` — extract URI SAN.

- [ ] **Test:** generated cert round-trips through `cert_to_x5c` → `identity_from_cert` == input identity; key is P-256.
- [ ] Implement with `cryptography` (`ec.generate_private_key(ec.SECP256R1())`, `x509.CertificateBuilder`, `SubjectAlternativeName([x509.UniformResourceIdentifier(identity)])`).
- [ ] Run tests → PASS. Commit: `feat: ephemeral ES256 keypair and self-signed cert helper`.

### Task 5: Signer — produce spec-native AgentCardSignature

**Files:** Create `src/ellingson_card/signer.py`; Test `tests/test_signer.py`.

**Interfaces — Produces:**
- `sign_card(card: AgentCard, key, cert, rekor_log_index: int | None = None) -> dict` — returns an `AgentCardSignature` dict `{protected, signature, header}`. `protected` = b64url(`{"alg":"ES256"}`). Detached-payload JWS: signing input = `b64url(protected) + "." + b64url(canonicalize(card))`; `signature` = b64url of the JOSE-format (R||S, 64-byte) ES256 signature. `header` = `{"x5c": [...], "rekorLogIndex": int?}` (custom field for Rekor linkage per spec note).
- `attach_signature(card: AgentCard, sig: dict) -> dict` — return card dump with `signatures: [sig]`.

**Consumes:** `canonicalize` (T3), `cert_to_x5c` (T4).

- [ ] **Test:** signing produces `protected`/`signature`/`header`; decoding `protected` yields `{"alg":"ES256"}`; `header.x5c` non-empty; signature length (raw) is 64 bytes after b64url-decode; re-signing identical card with same key+nonce-free input is verifiable (verified in T6).
- [ ] Implement: DER→raw signature conversion via `cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature` then fixed-width R||S; base64url without padding.
- [ ] Run tests → PASS. Commit: `feat: emit v1.0-spec-native AgentCardSignature (JWS/ES256)`.

### Task 6: Verifier — fail-closed, identity-pinned

**Files:** Create `src/ellingson_card/errors.py`, `src/ellingson_card/verifier.py`; Test `tests/test_verifier.py`.

**Interfaces — Produces:**
- `errors.py`: `class VerificationError(Exception)` + subclasses `MissingSignature`, `BadSignature`, `IdentityMismatch`, `MissingRekorEntry`, `CardExpired`.
- `verify_card(card_json: dict, *, expected_identity: str, require_rekor: bool = True, rekor_checker=default_rekor_checker, max_age=None) -> VerifyResult` — fails closed, raising the specific subclass. Returns `VerifyResult(identity, rekor_log_index, valid=True)` on success.
- `VerifyResult` dataclass: `identity: str`, `rekor_log_index: int | None`, `valid: bool`.

**Consumes:** `canonicalize` (T3), `identity_from_cert` (T4).

- [ ] **Tests (one per fail path):** valid card → `valid=True`; remove `signatures` → `MissingSignature`; flip one payload byte → `BadSignature`; sign with identity A, verify expecting B → `IdentityMismatch`; `require_rekor=True` with no `rekorLogIndex` → `MissingRekorEntry`; expired card with `max_age` → `CardExpired`.
- [ ] Implement: reconstruct detached signing input, verify ES256 against `x5c[0]` public key (raw→DER re-encode), pin `identity_from_cert(x5c[0]) == expected_identity`, enforce Rekor presence + checker, freshness check.
- [ ] Run tests → PASS. Commit: `feat: fail-closed identity-pinned verifier with distinct errors`.

### Task 7: Rekor inclusion checker

**Files:** Modify `src/ellingson_card/verifier.py` (add `default_rekor_checker`); Test extend `tests/test_verifier.py`.

**Interfaces — Produces:** `default_rekor_checker(log_index: int) -> bool` — confirms a Rekor entry exists (uses `sigstore`'s Rekor client against the public instance). Injected/mockable so local tests are hermetic.

- [ ] **Test:** a fake checker returning `False` → `MissingRekorEntry`; returning `True` → passes. (No network in tests.)
- [ ] Implement `default_rekor_checker` querying Rekor by log index; document that local hermetic demo passes `rekor_checker=lambda _: True` is NOT allowed — instead local demo runs with `require_rekor=False` and the README explains the CI path supplies the real entry.
- [ ] Run tests → PASS. Commit: `feat: Rekor inclusion checker (injectable)`.

### Task 8: Local serve at well-known path

**Files:** Create `src/ellingson_card/serve.py`; Test `tests/test_serve.py`.

**Interfaces — Produces:** `make_server(card_path: Path, port: int) -> HTTPServer` serving signed card at `/.well-known/agent-card.json` with `Content-Type: application/json`, `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`; 404 elsewhere.

- [ ] **Test:** start server on ephemeral port, GET well-known path → 200 + correct content-type + HSTS header + parseable card; GET other path → 404.
- [ ] Implement with `http.server.BaseHTTPRequestHandler` + threaded server fixture.
- [ ] Run tests → PASS. Commit: `feat: serve signed card at well-known path with security headers`.

### Task 9: CLI (sign / verify / serve)

**Files:** Create `src/ellingson_card/cli.py`; Test `tests/test_cli.py`. Modify `pyproject.toml` (script entry).

**Interfaces — Produces:** `ellingson-card sign|verify|serve` via argparse. `sign --in --out [--identity]`; `verify --in --identity [--no-require-rekor] [--max-age]`; `serve --card --port`. Exit non-zero with the error class name on failure (fail-closed visible to shell).

- [ ] **Test:** `sign` then `verify` round-trips (subprocess or direct `main([...])`); `verify` of tampered card exits non-zero printing `BadSignature`.
- [ ] Implement thin argparse wiring over Tasks 5/6/8.
- [ ] Run tests → PASS. Commit: `feat: CLI for sign/verify/serve`.

### Task 10: Makefile + hermetic demo

**Files:** Create `Makefile`; Test `tests/test_demo.py` (invokes `make demo` end-to-end, asserts exit 0 + verified output).

**Interfaces — Produces:** `make sign` (ephemeral key, identity pinning on), `make verify` (identity pinning on by default, `--no-require-rekor` for local), `make serve`, `make demo` (sign → verify → tamper → show fail), `make test`, `make lint`.

- [ ] **Test:** `make demo` exits 0; tamper step demonstrably fails verification (captured).
- [ ] Implement Makefile; demo prints signature validity AND pinned identity (DoD).
- [ ] Run → PASS. Commit: `feat: Makefile with hermetic make demo`.

### Task 11: Keyless signing workflow (CI)

**Files:** Create `.github/workflows/sign-card.yml`.

**Produces:** workflow that on tag/dispatch runs `sigstore` keyless signing of the card, embeds Fulcio `x5c` + Rekor log index into the `AgentCardSignature.header`, uploads the signed card artifact.

- [ ] Write workflow: `permissions: {id-token: write, contents: read}`, SHA-pinned actions, `astral-sh/setup-uv`, calls a `sign --keyless` path (add to signer/CLI: use `sigstore.sign` to obtain cert + Rekor entry, reuse `sign_card` framing). Document the JWS/Rekor seam (x5c via cert; Rekor index via custom header).
- [ ] `actionlint` + `zizmor` clean.
- [ ] Commit: `ci: keyless Sigstore signing workflow with OIDC`.

### Task 12: Docs — README, SPEC-VERIFIED, architecture, THREAT-COVERAGE, delivery hardening, SECURITY

**Files:** Create `README.md`, `SPEC-VERIFIED.md`, `SECURITY.md`, `docs/architecture.md`, `docs/THREAT-COVERAGE.md`, `docs/delivery-hardening.md`.

**Produces:** the honesty + provenance narrative satisfying R-B5, R-B6, and §5.4 DoD.

- [ ] `SPEC-VERIFIED.md`: v1.0.0 / 2026-06-22, well-known path + `AgentCardSignature` fields cited.
- [ ] `README.md`: lead with DNSSEC+CT delivery-channel differentiation; `make verify` output shows signature validity + pinned identity; "no long-lived keys — grep and see"; honest "demonstrated vs production scale"; disclose `sigstore-a2a` not used and why (D-B1).
- [ ] `THREAT-COVERAGE.md`: map each control → Project A threat (card spoofing/shadowing, card tampering via DNS/CDN, weak/optional auth).
- [ ] `docs/architecture.md`: sign → log → serve → verify trust-chain diagram (mermaid), showing where DNSSEC/CT attest delivery.
- [ ] `docs/delivery-hardening.md`: DNSSEC + CT pattern + `serve/` upgrade path (D-B2).
- [ ] `SECURITY.md`: disclosure contact + scope (local-only PoC).
- [ ] Commit: `docs: README, spec verification, threat coverage, delivery hardening`.

---

## Self-Review

**Spec coverage (PRD §5):** R-B1 (sign/verify/serve, pinning default-on) → T5/6/9/10. R-B2 (no long-lived keys) → T11 + README. R-B3 (OIDC, SHA pins, least priv) → T11. R-B4 (fail-closed, distinct errors) → T6/7. R-B5 (THREAT-COVERAGE) → T12. R-B6 (arch doc + diagram) → T12. §5.2 components 1–5 → T2/T11/T6/T11/T12. DoD §5.4: clean-clone verify shows identity → T10/12; one-byte tamper fails → T6; wrong-identity fails pinning → T6; Rekor checked → T7; signature v1.0-native → T5; README honesty → T12; SPEC-VERIFIED → T12. **All covered.**

**Open decisions surfaced for the user before/around T11:** whether to create the GitHub remote + run the real keyless workflow (outward-facing) — hold and ask.
