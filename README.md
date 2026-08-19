# CyberTriageAI — public front end

Static, read-only front end for [CyberTriageAI](https://github.com/inspiretravel/soc-dashboard): real attacks on a
single Australian honeypot, auto-triaged into MITRE ATT&CK-mapped cases. Portfolio project for a SOC L1 / Security
Analyst job search in Australia.

**This repo holds no secrets and never calls the Claude API.** It renders finished triage output only.

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing — pain → solution, live map, how it works, statistics, inside the tool, about teaser |
| `dashboard.html` | Priority queue (last 24h, grouped by ATT&CK technique) |
| `attack-map.html` | D3 globe: origin countries → Australian node |
| `cases.html` | AI-written cases: what happened · why it matters · what to do next |
| `reference.html` | Same evidence mapped to ATT&CK, Essential Eight, NIST CSF 2.0, ISO/IEC 27001:2022 |
| `about.html` | Architecture, methodology, tech stack, honesty notes |
| `assets/data.js` | **Single source of truth** for every number on the site |
| `assets/figures.js` | Top-level figures supplied from the live DB (all-time total, unique IPs) |
| `assets/site.js` | Shared helpers: escaped DOM builder, nav, footer disclaimer, MITRE links, derived stats, **live-feed fetch → map → fallback** |
| `assets/config.js` | `apiUrl` of the read-only feed (`/api/public/attacks`). No secrets. `""` forces the built-in sample |
| `check_invariants.py` | Rejects the build if INV1–INV5 fail, a placeholder is unfilled, or a MITRE ID is invalid |
| `_headers` | Cloudflare Pages security headers (CSP etc.) |

## Rules this front end follows

- All data is rendered through `textContent` / `createElement` — never `innerHTML` — so attacker-derived text
  (IPs, payloads, technique names) is escaped by construction.
- Every MITRE technique badge links to `attack.mitre.org`.
- One honeypot node, Australia (city never named), region-level marker; no hostnames or internal IPs.
- Footer on every page: *AI-generated triage — portfolio demo. Human review required before action.*

## Live data

Every page calls `Site.ready(...)`, which fetches `CONFIG.apiUrl` (5 s timeout) and maps the payload into the
same shape `data.js` uses. If the feed is unreachable the page renders the built-in sample and the header pill
says **sample data**. Live pages say **live · refreshed Ns ago**. Nothing on the site can trigger a model call.

## Before merging to `main`

1. `python check_invariants.py --live https://<host>/api/public/attacks` — must print `OK`
   (checks INV1–INV5 against the real payload; stale-summary INV5 mismatches are WARN).
2. Optionally fill `assets/figures.js` so the *sample* fallback also passes `python check_invariants.py`.

## Deploy (Cloudflare Pages)

Framework preset **None** · build command *(none)* · output directory **/**.
