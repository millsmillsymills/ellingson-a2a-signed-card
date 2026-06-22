# Security policy

This repository is a research and demonstration artifact, not a deployed service.
All demos run against local, operator-owned targets only.

## Reporting

If you find a flaw in the signing or verification logic, please open a
private security advisory on the repository (Security → Advisories) rather than a
public issue. Include the card or signature input that reproduces the problem.

## Scope and honest limits

- The local sign/verify path uses an ephemeral self-signed certificate and is not
  transparency-logged; it exists for offline demonstration. Production-style
  provenance comes from the Sigstore keyless workflow.
- `sigstore` is a dependency for the keyless path; review its own advisories.
- The DNSSEC/CT delivery-channel attestation is documented against the real
  pattern; this repo serves the card locally (see `docs/delivery-hardening.md`).
