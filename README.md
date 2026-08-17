# CyberTriageAI — public front end

Static, read-only front end for [CyberTriageAI](https://github.com/inspiretravel/soc-dashboard): real attacks on a
single Melbourne honeypot, auto-triaged into MITRE ATT&CK-mapped cases. Portfolio project for a SOC L1 / Security
Analyst job search in Australia.

**This repo holds no secrets and never calls the Claude API.** It renders finished triage output only.

## Files

| File | Purpose |
|---|---|
| `index.html` | Landing — pain → solution, live map, how it works, statistics, inside the tool, about teaser |
| `dashboard.html` | Priority queue (last 24h, grouped by ATT&CK technique) |
| `attack-map.html` | D3 globe: origin countries → Melbourne node |
| `cases.html` | AI-written cases: what happened · why it matters · what to do next |
| `reference.html` | Same evidence mapped to ATT&CK, Essential Eight, NIST CSF 2.0, ISO/IEC 27001:2022 |
| `about.html` | Architecture, methodology, tech stack, honesty notes |
| `assets/data.js` | **Single source of truth** for every number on the site |
| `assets/figures.js` | Top-level figures supplied from the live DB (all-time total, unique IPs) |
| `assets/site.js` | Shared helpers: escaped DOM builder, nav, footer disclaimer, MITRE links, derived stats |
| `check_invariants.py` | Rejects the build if INV1–INV5 fail, a placeholder is unfilled, or a MITRE ID is invalid |
| `_headers` | Cloudflare Pages security headers (CSP etc.) |

## Rules this front end follows

- All data is rendered through `textContent` / `createElement` — never `innerHTML` — so attacker-derived text
  (IPs, payloads, technique names) is escaped by construction.
- Every MITRE technique badge links to `attack.mitre.org`.
- One honeypot node, Melbourne, region-level marker; no hostnames or internal IPs.
- Footer on every page: *AI-generated triage — portfolio demo. Human review required before action.*

## Before merging to `main`

1. Fill `assets/figures.js` from the live database.
2. Run `python check_invariants.py` — must print `OK`.

## Deploy (Cloudflare Pages)

Framework preset **None** · build command *(none)* · output directory **/**.
