# Threat coverage

Each control here maps back to a threat from the companion A2A threat-model research.
Enforcement status notes whether the A2A spec mandates, recommends, or is silent
on the control — the gap this repo closes by enforcing it.

| A2A threat | Control in this repo | Where | Spec status |
|------------------|----------------------|-------|-------------|
| Card spoofing / shadowing (a stranger serves a card claiming to be us) | Identity pinning: the verifier requires the signing cert's URI SAN to equal the expected workflow identity; an unpinned verifier is rejected by default | `verifier.py` (`IdentityMismatch`) | Recommended, not mandated |
| Forged self-signed cert carrying the right URI SAN | Optional trust anchoring: with a configured `trust_root`, the leaf must chain to a trusted Fulcio root (validity + CA constraints + signature at each hop) and its Fulcio OIDC-issuer extension must match; a self-signed cert is rejected. Absent a trust root, the hermetic self-signed path is kept | `trust.py`, `verifier.py` (`UntrustedCertificate`) | Silent |
| Card tampering via DNS/CDN compromise (bytes altered in transit) | Detached JWS over the JCS canonical card: any one-byte change fails verification | `signer.py`, `verifier.py` (`BadSignature`) | Signature recommended in v1.0 |
| Signature present but never publicly logged (undetectable key misuse) | Rekor inclusion is verified offline from the proof and signed checkpoint in the keyless card's Sigstore bundle, bound to the artifact being verified — not assumed from a header index, and not a re-fetch by index that breaks across the v1→v2 log migration | `keyless_verify.py`, `verifier.py` (`BundleVerificationError`) | Silent |
| Card signed via an unexpected OIDC provider Fulcio trusts (same SAN, different issuer) | OIDC issuer pinning on the keyless bundle path: `expected_oidc_issuer` is required, so the bundle's Fulcio OIDC-issuer extension must match the expected provider — verification fails closed if it is absent | `keyless_verify.py`, `verifier.py` (`BundleVerificationError`) | Silent |
| Long-lived signing key theft | Keyless signing: Fulcio short-lived certs, no persisted private key | `keyless.py`, `sign-card.yml` | Silent |
| Stale / replayed card after key rotation | Freshness bound to the signing cert validity window (Fulcio certs are short-lived) | `verifier.py` (`CardExpired`) | Silent |
| Weak / optional transport | Card endpoints must be HTTPS; served with HSTS and `nosniff` | `card.py`, `serve.py` | Recommended |
| Compromised delivery channel below the card layer | DNSSEC on the serving zone + CT monitoring of the endpoint TLS cert | `docs/delivery-hardening.md` | Out of A2A scope (the gap) |

The bottom row is the differentiated contribution: A2A says nothing about
attesting the channel the card is delivered over, so a card can be perfectly
signed yet served from a hijacked endpoint. DNSSEC + CT close that gap.
