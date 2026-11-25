# Security Center Gateway — Preview

This folder contains a temporary Preview-only gateway implementation for the unified Network Intelligence & Security Center.

> Repository placement note: GitHub's connected integration does not expose a repository-creation operation in this session. To keep source reviewable without changing `main`, the first gateway source is staged under this isolated folder in the Rule-Provider integration PR. It should move unchanged into a dedicated `zskbot/security-center-gateway` repository when repository creation is available. No Rule-Provider generator or data files are changed.

## Runtime
- Cloudflare Worker: `security-center-gateway-preview`
- Public URL is assigned by Cloudflare after Preview deployment.
- Read-only GET/HEAD/OPTIONS; no database, no KV, no queues, no writes.
- No GitHub Actions deployment.
- No custom domain or DNS configuration.

## Endpoints
- `GET /health` — runtime status and adapter gates.
- `GET /health/deep` — bounded HEAD checks against Rule-Provider artifact and IANA RDAP bootstrap.
- `GET /v1/catalog` — enabled/restricted/disabled adapter inventory.
- `GET /v1/rules/providers/geoip/{CC}` — verified path metadata and direct source URL.
- `GET /v1/rules/providers/site/{CC}` — verified path metadata and direct source URL.
- `GET /v1/rules/adblock/catalog` — catalog metadata only; no content proxy until licensing is verified.
- `GET /v1/intel/domain/lookup?name=example.com` — IANA RDAP bootstrap lookup.

## Data and license boundaries
- Rule-Provider README declares MIT for source code and attributes generated data to RIRs, IPtoASN, v2fly/domain-list-community and Chrome CrUX/PSL. The gateway returns direct source URLs and does not mirror generated artifacts; data redistribution terms still require source-by-source confirmation.
- clash-AdsBlock has no root LICENSE file. Only metadata and upstream links are exposed; content delivery is disabled. NSFW lists are excluded.
- RDAP queries are live read-only requests to the authoritative RDAP service selected by IANA bootstrap. The gateway does not bundle or claim to execute the `@aoxborrow/rdap-whois` package, nor does it provide WHOIS fallback in this first Preview.
- PhishGuard and Email Security are disabled.

## Safeguards
- Domain input is normalized and validated; no caller-controlled upstream URL.
- Upstream requests use fixed HTTPS origins and bounded timeouts.
- Best-effort per-isolate rate limit: 30 requests per minute per client IP. This is not a globally consistent quota and must be replaced with a platform-level control before wider exposure.
- Public wildcard CORS is used only because every exposed operation is read-only and unauthenticated; credentials are never allowed.
- No user data is persisted. RDAP responses are not cached by the gateway.
- This is an engineering Preview, not a production security verdict service.

## Verification checklist
- [ ] Worker deploy metadata points to this branch commit.
- [ ] `/health` returns 200.
- [ ] `/health/deep` verifies upstream connectivity and timeout behavior.
- [ ] GeoIP/site metadata routes validate country codes and return direct source links.
- [ ] AdBlock catalog exposes no list body.
- [ ] RDAP valid-domain, invalid-domain, unsupported-TLD, timeout and upstream-error cases are checked.
- [ ] OPTIONS preflight and CORS headers are checked.
- [ ] 31st request within the same isolate window returns 429 (best effort).
- [ ] Confirm no Production environment, DNS, paid add-on, database or GitHub Actions deployment was touched.
