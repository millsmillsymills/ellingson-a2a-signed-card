# Delivery-channel hardening (DNSSEC + CT)

A signed Agent Card proves the *bytes* are authentic. It says nothing about the
*channel* they arrived over. An attacker who controls DNS or the CDN can still
point `a2a.example` at their own endpoint; if the consumer never signed up for
channel attestation, a validly-signed card served from a hijacked host looks
fine. This is the gap A2A leaves open, and the part this project treats as the
contribution.

## The two channel attestations

1. **DNSSEC on the serving zone.** The zone that publishes the well-known host is
   DNSSEC-signed, so a resolver can detect forged `A`/`AAAA`/`CNAME` answers. A
   consumer (or a monitor) that requires the AD bit rejects a spoofed delivery
   address before it ever fetches the card.

2. **Certificate Transparency monitoring of the endpoint TLS cert.** The TLS
   certificate for the serving host is watched in CT logs. An unexpected
   certificate issued for the host — the signal of a CDN/DNS takeover or a
   mis-issuance — is detected out of band, independent of the card signature.

Together they bind card trust to the delivery channel: the card is signed, the
name resolves only to the DNSSEC-attested address, and the TLS identity at that
address is CT-monitored.

## Serving model

Per the project decision, the card is served **locally** (`make serve`) rather
than live from production infrastructure. A public repo that live-serves from
real infra turns that infra into an advertised attack surface for no benefit the
documented pattern can't convey. The DNSSEC/CT design is described and diagrammed
against the real pattern; see [architecture.md](architecture.md).

## Upgrade path to live serving

To flip this to a live-served card later:

1. Publish `signed-card.json` at `https://<host>/.well-known/agent-card.json`
   behind the DNSSEC-signed zone.
2. Enable HSTS preload and ensure no plaintext fallback (the local server already
   sets HSTS + `nosniff`).
3. Add the endpoint's TLS cert to a CT monitor (e.g. a `certstream`-style watch)
   and alert on unexpected issuers.
4. Keep the keyless signing workflow as the only signer; never introduce a
   long-lived key for convenience.
