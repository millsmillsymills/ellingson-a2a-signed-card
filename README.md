# ellingson-a2a-signed-card

A reference implementation that serves an [A2A](https://a2a-protocol.org) v1.0
Agent Card whose trust is bound to its **delivery channel** — DNSSEC on the
serving domain and Certificate-Transparency monitoring of the endpoint's TLS
cert — on top of keyless, transparency-logged signing.

Keyless signing, identity pinning, and Rekor inclusion already exist in other
tooling. The angle here is pairing those with **delivery-channel attestation**
(DNSSEC + CT) and emitting a **v1.0-spec-native `AgentCardSignature`** rather
than a tool-specific wrapper. See [docs/delivery-hardening.md](docs/delivery-hardening.md).

> Framing: this is a threat-modeling and provenance demonstration that reuses
> real OIDC/CT/DNSSEC infrastructure patterns. It is early-and-informed work, not
> a battle-tested production deployment. The card is served locally
> ([why](docs/delivery-hardening.md#serving-model)); the DNSSEC/CT story is
> documented and diagrammed against the real pattern.

## What it does

- Emits a spec-native `AgentCardSignature` — RFC 7515 JWS (ES256) with a detached
  payload over the RFC 8785 (JCS) canonical card, excluding the `signatures`
  field, per A2A v1.0 §8.4. See [SPEC-VERIFIED.md](SPEC-VERIFIED.md).
- Signs **keyless** in CI: GitHub OIDC → Fulcio short-lived cert (in the JWS
  `x5c` header) → Rekor transparency-log entry, with the full Sigstore bundle
  (cert chain plus the Rekor inclusion proof) carried in a `sigstoreBundle`
  header field. No long-lived keys exist in the repo or CI:

  ```
  $ rg -i "BEGIN.*PRIVATE KEY" src/
  # (no matches — signing keys are short-lived and never persisted)
  ```

- Verifies **fail-closed with identity pinning on by default**. Each failure has
  a distinct error: `MissingSignature`, `BadSignature`, `IdentityMismatch`,
  `UntrustedCertificate`, `MissingRekorEntry`, `BundleVerificationError`,
  `CardExpired`.
- Serves the card at the v1.0 well-known path `/.well-known/agent-card.json` with
  HSTS and `X-Content-Type-Options: nosniff`.

## Quickstart

```bash
uv sync
make demo      # sign -> verify -> tamper -> reject (hermetic, offline)
make test
make lint
```

`make demo` output:

```
== sign ==
signed card written to <tmp>/signed-card.json (ephemeral key, identity: …/local-dev)
== verify (valid card) ==
OK: signature valid; pinned identity https://ellingson-security.example/local-dev
    rekor log index: None
== tamper one field and re-verify (must be rejected) ==
BadSignature: signature does not match canonical card
tampered card correctly rejected
```

## Local vs CI signing

The local `make sign`/`make demo` path uses an **ephemeral P-256 key + a
self-signed cert** carrying the signer identity as a URI SAN — so the demo runs
offline with no network or secrets. That signature is not in Rekor, so local
verification runs with `--no-require-bundle` while identity pinning stays on.

The real provenance path runs in [`.github/workflows/sign-card.yml`](.github/workflows/sign-card.yml):
Sigstore keyless signing produces a Fulcio cert and a Rekor entry, and the card
is then verified with **Rekor inclusion required**, the workflow identity
pinned, and the Fulcio OIDC issuer pinned with `--oidc-issuer` (required when
verifying a bundle card, so an unexpected OIDC provider Fulcio trusts cannot mint
a cert for the same identity). "Rekor inclusion is checked, not assumed" — the
verifier hands the embedded Sigstore bundle to Sigstore's offline verifier, which
confirms the inclusion proof and signed checkpoint bind to the artifact being
verified. Because
the proof travels in the bundle rather than being re-fetched by index, this stays
correct across Rekor's v1→v2 migration (Sigstore staging already signs to v2).

To cryptographically anchor trust to a Fulcio root instead of string-matching a
self-signed cert, pass `verify --trust-root <fulcio-roots.pem> --oidc-issuer
<issuer>`: the leaf is then chained to a trusted anchor and its Fulcio
OIDC-issuer extension is pinned. The two flags are required together.

## Why not `sigstore-a2a`?

`RedDotRocket/sigstore-a2a` wraps the card as `{agentCard, verificationMaterial}`
with an in-toto DSSE predicate and a `protocolVersion: "0.2.9"` example — it does
not emit the v1.0 `signatures[]` / `AgentCardSignature` JWS shape, and it is
self-described prototype, unaudited code. So this repo implements spec-native
JWS-over-JCS directly on the upstream `sigstore` and `cryptography` libraries (no
novel crypto). See [docs/architecture.md](docs/architecture.md).

## Layout

| Path | Responsibility |
|------|----------------|
| `cards/ellingson-agent-card.json` | The spec-valid v1.0 Agent Card |
| `src/ellingson_card/canonical.py` | RFC 8785 JCS canonicalization |
| `src/ellingson_card/signer.py` | Emit the spec-native `AgentCardSignature` |
| `src/ellingson_card/keyless.py` | Sigstore keyless adapter (CI) |
| `src/ellingson_card/verifier.py` | Fail-closed, identity-pinned verifier |
| `src/ellingson_card/keyless_verify.py` | Offline Sigstore bundle verification (keyless) |
| `src/ellingson_card/serve.py` | Serve at the well-known path |
| `docs/` | Architecture, threat coverage, delivery hardening |

Licensed under Apache-2.0.
