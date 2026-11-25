# Preview deployment record

- Worker: `security-center-gateway-preview`
- Cloudflare account: existing linked account; no account or plan changes made
- Version: `6e174d0b-6ad1-46df-b8ea-afc73d050940`
- Version number: `1`
- Deployment ID: `11166eb0-9312-49c4-8789-ac2ddc5e63b3`
- Source: Cloudflare API upload from `feat/security-center-gateway-preview`
- Usage model: `standard` (existing account setting; paid usage may apply)
- Worker `workers.dev` route: disabled
- Version Preview URLs: enabled
- No custom domain, DNS record, Production hostname, database, KV, D1, R2, or external binding configured

## Version URL

`https://6e174d0b-security-center-gateway-preview.huynhthuongg2505-f9b.workers.dev`

This is a versioned Preview URL for the uploaded version. It is not a full isolated Workers Previews branch environment. The Worker has no bindings or persistence, so it cannot access Production databases or storage.

## Verification status

- [x] Cloudflare accepted the module upload and created version 1.
- [x] Cloudflare reports `has_preview: true`.
- [x] `workers.dev` route is disabled; version preview setting is enabled.
- [x] Worker settings report `usage_model: standard`, no bindings, and observability disabled.
- [ ] Runtime HTTP health check — not independently confirmed. The connected execution environment blocks outbound requests to the account's own `workers.dev` host; browser retrieval also did not complete.
- [ ] CORS preflight — not runtime-verified.
- [ ] Upstream timeout behavior — not runtime-verified.
- [ ] 31st-request rate-limit behavior — not runtime-verified. The current in-memory limiter is best-effort per isolate, not a globally consistent quota.

Do not treat source inspection or successful upload as proof of runtime acceptance. The Worker remains a public, unauthenticated, read-only Preview endpoint; do not put sensitive data behind it.
