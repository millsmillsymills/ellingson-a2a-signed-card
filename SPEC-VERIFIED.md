# Spec verification record

**A2A spec version:** v1.0.0
**Verified against the live spec on:** 2026-06-22
**Source:** https://a2a-protocol.org/v1.0.0/specification/ and the v1.0 release notes
(https://a2a-protocol.org/latest/whats-new-v1/).

## What was checked before writing protocol code

| Item | Verified value |
|------|----------------|
| Well-known path | `/.well-known/agent-card.json` |
| Signature object | `AgentCardSignature` = `{protected (req), signature (req), header (opt)}` (§4.4.7) |
| Signature format | RFC 7515 JWS, detached payload |
| Canonicalization | RFC 8785 JCS, computed over the card **with `signatures` excluded** |
| Signature algorithm | ES256 (ECDSA P-256 + SHA-256) |
| Card structure | `supportedInterfaces[]` (each with `protocolBinding` + `protocolVersion`), `securitySchemes`, `signatures[]` |
| Protocol version | `"1.0"` (Major.Minor; carried per interface) |
| OAuth | Authorization Code with `pkceRequired`; implicit/password removed in v1.0 |

The proto field names (`supportedInterfaces`, `securitySchemes`, the
`AgentCardSignature` fields) were cross-checked against `a2a-sdk==1.1.0`'s
protobuf descriptors. The served card is authored as spec JSON; canonicalization
operates on the served bytes so that what is signed is exactly what is served.
