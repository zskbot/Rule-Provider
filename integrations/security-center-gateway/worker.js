const VERSION = "0.1.0-preview";
const WINDOW_MS = 60_000;
const LIMIT = 30;
const buckets = new Map();
const ALLOWED_METHODS = "GET, HEAD, OPTIONS";
const ALLOWED_HEADERS = "Accept, Content-Type";

function cors(origin) {
  // Public, read-only API: wildcard CORS is intentional; never enable credentials.
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": ALLOWED_METHODS,
    "Access-Control-Allow-Headers": ALLOWED_HEADERS,
    "Access-Control-Max-Age": "600",
    "Vary": "Origin",
  };
}
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
function limited(request) {
  const key = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  let bucket = buckets.get(key);
  if (!bucket || now - bucket.start >= WINDOW_MS) bucket = { start: now, count: 0 };
  bucket.count++;
  buckets.set(key, bucket);
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) if (now - v.start >= WINDOW_MS) buckets.delete(k);
  }
  return bucket.count > LIMIT;
}
async function timedFetch(url, ms = 5000, init = {}) {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms), redirect: "manual" });
}
function validDomain(input) {
  if (typeof input !== "string" || input.length > 253) return null;
  const value = input.trim().toLowerCase().replace(/\.$/, "");
  if (!value || value.includes("/") || value.includes(":") || value.includes("@")) return null;
  try {
    const host = new URL("https://" + value).hostname;
    if (host !== value || !value.includes(".") || value.split(".").every(x => /^\\d+$/.test(x)) || value.split(".").some(x => !x || x.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x))) return null;
    return value;
  } catch { return null; }
}
function ruleCatalog(kind, country) {
  if (!/^[A-Z]{2}$/.test(country)) return null;
  const path = kind === "geoip"
    ? `ruleset/geoip/Clash/${country}.yaml`
    : `ruleset/site/Clash/${country}.yaml`;
  return {
    provider: "Rule-Provider",
    kind,
    country,
    format: "mihomo-clash-yaml",
    source_url: `https://raw.githubusercontent.com/zskbot/Rule-Provider/main/${path}`,
    delivery: "direct-source-link",
    mirrored_by_gateway: false,
    provenance: "RIR delegated data / upstream domain datasets; consult source README and metadata",
    license: "Repository code MIT; generated data provenance and redistribution terms require per-source review",
  };
}
async function rdapLookup(domain) {
  const bootstrapRes = await timedFetch("https://data.iana.org/rdap/dns.json", 5000, { headers: { Accept: "application/json" } });
  if (!bootstrapRes.ok) throw new Error("RDAP bootstrap unavailable");
  const bootstrap = await bootstrapRes.json();
  const tld = domain.split(".").at(-1);
  const service = (bootstrap.services || []).find(item => Array.isArray(item[0]) && item[0].some(x => String(x).toLowerCase() === tld));
  if (!service || !Array.isArray(service[1]) || !service[1].length) return { unsupported: true };
  const secureBase = service[1].find(candidate => { try { return new URL(candidate).protocol === "https:"; } catch { return false; } });
  if (!secureBase) return { unsupported: true, reason: "no_https_rdap_endpoint" };
  const base = new URL(secureBase);
  const endpoint = new URL("domain/" + encodeURIComponent(domain), base.href.endsWith("/") ? base : base.href + "/");
  const response = await timedFetch(endpoint.href, 7000, { headers: { Accept: "application/rdap+json, application/json" } });
  if (response.status === 404) return { not_found: true, source: endpoint.origin };
  if (!response.ok) throw new Error("Registry RDAP returned " + response.status);
  const data = await response.json();
  const registrar = (data.entities || []).find(e => (e.roles || []).includes("registrar"));
  const registrarName = registrar?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || null;
  const events = (data.events || []).map(e => ({ action: e.eventAction, date: e.eventDate }));
  return {
    domain,
    handle: data.handle || null,
    ldh_name: data.ldhName || domain,
    status: data.status || [],
    registrar: registrarName,
    events,
    nameservers: (data.nameservers || []).map(n => n.ldhName).filter(Boolean),
    secure_dns: data.secureDNS || null,
    source: endpoint.origin,
    queried_at: new Date().toISOString(),
    raw_response_included: false,
  };
}
async function handle(request) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(request.headers.get("Origin")) });
  if (!["GET", "HEAD"].includes(request.method)) return json({ error: "method_not_allowed" }, 405, { Allow: ALLOWED_METHODS });
  if (limited(request)) return json({ error: "rate_limited", limit: LIMIT, window_seconds: 60 }, 429, { "Retry-After": "60" });

  if (url.pathname === "/" || url.pathname === "/health") {
    return json({ service: "security-center-gateway", version: VERSION, status: "ok", mode: "preview", methods: ALLOWED_METHODS, write_operations: false, data_persistence: false, adapters: { rule_provider: "read-only-source-links", adblock: "catalog-only-license-pending", rdap: "read-only-live-lookup", phish_guard: "disabled", email_security: "disabled" } }, 200, { "Cache-Control": "public, max-age=30" });
  }
  if (url.pathname === "/health/deep") {
    const checks = await Promise.all([
      timedFetch("https://raw.githubusercontent.com/zskbot/Rule-Provider/main/ruleset/geoip/Clash/CN.yaml", 5000, { method: "HEAD" }).then(r => ({ name: "rule-provider-cn", ok: r.ok, status: r.status })).catch(() => ({ name: "rule-provider-cn", ok: false, error: "timeout_or_network_error" })),
      timedFetch("https://data.iana.org/rdap/dns.json", 5000, { method: "HEAD" }).then(r => ({ name: "iana-rdap-bootstrap", ok: r.ok, status: r.status })).catch(() => ({ name: "iana-rdap-bootstrap", ok: false, error: "timeout_or_network_error" })),
    ]);
    return json({ service: "security-center-gateway", status: checks.every(x => x.ok) ? "ok" : "degraded", checks, adblock: "not_probed_license_unverified" }, checks.every(x => x.ok) ? 200 : 503);
  }
  if (url.pathname === "/v1/catalog") {
    return json({ version: VERSION, adapters: [
      { id: "rule-provider", status: "enabled", mode: "link-only", endpoints: ["/v1/rules/providers/geoip/{CC}", "/v1/rules/providers/site/{CC}"] },
      { id: "clash-adblock", status: "restricted", mode: "catalog-only", reason: "No repository LICENSE file found; no content redistribution or proxying" , endpoint: "/v1/rules/adblock/catalog" },
      { id: "rdap-whois", status: "enabled", mode: "RDAP-only-preview", endpoint: "/v1/intel/domain/lookup?name=example.com", note: "Uses IANA RDAP bootstrap; does not bundle the rdap-whois npm package or perform WHOIS TCP fallback" },
      { id: "phish-guard", status: "disabled", reason: "Security hardening and model provenance pending" },
      { id: "analysis-spf-dmarc", status: "disabled", reason: "DKIM key incident and Git history remediation pending" },
    ] }, 200, { "Cache-Control": "public, max-age=60" });
  }
  const ruleMatch = url.pathname.match(/^\/v1\/rules\/providers\/(geoip|site)\/([A-Za-z]{2})$/);
  if (ruleMatch) {
    const item = ruleCatalog(ruleMatch[1], ruleMatch[2].toUpperCase());
    return item ? json(item, 200, { "Cache-Control": "public, max-age=300" }) : json({ error: "invalid_country_code" }, 400);
  }
  if (url.pathname === "/v1/rules/adblock/catalog") {
    const lists = ["oisd_small.txt", "oisd_big.txt", "ABPindo.txt", "notrack.txt", "dns.txt"].map(file => ({
      id: file.replace(/\.txt$/, ""),
      source_url: `https://raw.githubusercontent.com/zskbot/clash-AdsBlock/main/${file}`,
      license_status: "not_verified",
      gateway_content_access: false,
    }));
    return json({ provider: "clash-AdsBlock", status: "catalog_only", reason: "No LICENSE file found at repository root; confirm upstream source and redistribution terms before serving list content", lists, excluded: ["oisd_nsfw.txt", "oisd_nsfw_small.txt"] }, 200, { "Cache-Control": "public, max-age=300" });
  }
  if (url.pathname === "/v1/intel/domain/lookup") {
    const domain = validDomain(url.searchParams.get("name"));
    if (!domain) return json({ error: "invalid_domain", expected: "A normalized domain name, e.g. example.com" }, 400);
    try {
      const result = await rdapLookup(domain);
      if (result.unsupported) return json({ error: "rdap_not_supported_for_tld", domain }, 404);
      if (result.not_found) return json({ error: "domain_not_found", domain, source: result.source }, 404);
      return json({ provider: "IANA RDAP bootstrap", result }, 200, { "Cache-Control": "no-store" });
    } catch (error) {
      return json({ error: "rdap_upstream_error", message: error instanceof Error ? error.message : "unknown_error" }, 502);
    }
  }
  return json({ error: "not_found", path: url.pathname }, 404);
}
export default {
  async fetch(request) {
    const headers = cors(request.headers.get("Origin"));
    try {
      const response = await handle(request);
      const merged = new Headers(response.headers);
      for (const [k, v] of Object.entries(headers)) merged.set(k, v);
      if (request.method === "HEAD") return new Response(null, { status: response.status, headers: merged });
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: merged });
    } catch {
      return json({ error: "internal_error" }, 500, headers);
    }
  },
};
