# Security Center integration contract — Rule-Provider

## Audit snapshot
- Existing project is a deterministic rule-set generator for geoip and geosite/site rules.
- Inputs include the five RIR delegated extended feeds, IPtoASN, v2fly/domain-list-community and country top-site data.
- Outputs are generated for Surge, Clash, QuantumultX and Loon under `ruleset/`.
- `Makefile` exposes `test`, `fetch`, `generate`, `validate`, `check`, and `all`; `run_tests.py` is a zero-third-party-dependency test runner.
- The repository is large (GitHub metadata reports about 1.17 GB). Do not mirror or clone its full generated history into the gateway.

## Integration role
Rule-Provider is the static network-policy catalogue. The unified service must consume published, versioned rule artifacts by URL and metadata; it must not regenerate them on API requests.

## Preview API contract
The gateway adapter may expose:
- `GET /v1/rules/providers` — supported provider formats and catalogue metadata.
- `GET /v1/rules/providers/{format}/{scope}/{country}` — redirect/proxy to an existing published artifact only after its exact upstream path is verified.
- `GET /v1/rules/metadata` — return the source metadata with provenance and generated-at timestamp.

Responses must preserve source provenance, format, country code, content hash/ETag where available, and upstream last-modified information. Cache immutable versioned artifacts; do not invent missing country files.

## Guardrails
- No rewriting or rehosting of generated rule content without confirming license/provenance.
- Do not treat country IP allocation as geolocation certainty.
- No automatic policy enforcement or blocking from the preview API.
- No GitHub Actions deployment; external Preview infrastructure owns runtime deployment.
- Production, DNS and paid services are out of scope.
