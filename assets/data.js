/* CyberTriageAI — single source of truth for all displayed data.
 *
 * Every page reads from window.DATA. Derived numbers (24h totals, severity
 * mix, per-case findings/IP/technique counts, tactic coverage) are COMPUTED
 * from the rows below at render time — never typed in twice.
 *
 * STATUS: the row values are DEMO figures carried over from the design export.
 * PS replaces `queue[].n`, `queue[].ips`, `queue[].countries` and the case
 * evidence tables with live-DB values before merge. `check_invariants.py`
 * enforces INV1–INV5 against whatever is in this file.
 *
 * The block between DATA_BEGIN / DATA_END must stay valid JSON (no comments,
 * no trailing commas) so the Python checker can parse it.
 */
window.DATA = /* DATA_BEGIN */ {
  "brand": "CyberTriageAI",
  "node": "a single honeypot node in Melbourne, Australia",
  "nodeShort": "Melbourne, AU",
  "nodeCoord": [144.9631, -37.8136],
  "mitreTechniqueCount": 697,

  "tactics": [
    "Reconnaissance", "Resource development", "Initial access", "Execution",
    "Persistence", "Privilege escalation", "Defense evasion", "Credential access",
    "Discovery", "Lateral movement", "Collection", "Command and control",
    "Exfiltration", "Impact"
  ],

  "queue": [
    { "id": "T1190", "name": "Exploit public-facing application", "sev": "CRITICAL", "tactic": "Initial access", "n": 98824, "ips": 4, "countries": 3, "ago": "1m ago",
      "read": "Attempts to exploit an exposed service — check whether you actually run what they are aiming at.",
      "members": [ { "ip": "34.78.74.222", "c": "Belgium", "n": 576, "ago": "1m" }, { "ip": "34.77.48.240", "c": "Belgium", "n": 288, "ago": "2m" }, { "ip": "180.181.251.100", "c": "Australia", "n": 288, "ago": "4m" }, { "ip": "71.6.232.28", "c": "United States", "n": 288, "ago": "6m" } ] },
    { "id": "T1021.002", "name": "SMB / Windows admin shares", "sev": "CRITICAL", "tactic": "Lateral movement", "n": 42084, "ips": 1, "countries": 1, "ago": "1m ago",
      "read": "Post-compromise behaviour. This is the one to look at first.",
      "members": [ { "ip": "20.65.224.144", "c": "United States", "n": 864, "ago": "1m" } ] },
    { "id": "T1110", "name": "Brute force", "sev": "HIGH", "tactic": "Credential access", "n": 8213, "ips": 6, "countries": 5, "ago": "3m ago",
      "read": "Low skill, high volume. Noise unless it succeeds.",
      "members": [ { "ip": "77.72.5.234", "c": "United Kingdom", "n": 288, "ago": "9m" }, { "ip": "94.154.43.66", "c": "Türkiye", "n": 240, "ago": "12m" }, { "ip": "45.9.148.12", "c": "Netherlands", "n": 190, "ago": "15m" } ] },
    { "id": "T1078", "name": "Valid accounts", "sev": "HIGH", "tactic": "Persistence", "n": 3140, "ips": 3, "countries": 3, "ago": "6m ago",
      "read": "Credentials that worked somewhere else are being tried here.",
      "members": [ { "ip": "94.154.43.66", "c": "Türkiye", "n": 288, "ago": "12m" }, { "ip": "103.71.20.4", "c": "Viet Nam", "n": 121, "ago": "22m" } ] },
    { "id": "T1059.004", "name": "Unix shell", "sev": "HIGH", "tactic": "Execution", "n": 2044, "ips": 2, "countries": 2, "ago": "11m ago",
      "read": "Commands run after a successful exploit — check what they asked for.",
      "members": [ { "ip": "185.220.101.9", "c": "Germany", "n": 142, "ago": "11m" }, { "ip": "20.65.224.144", "c": "United States", "n": 96, "ago": "19m" } ] },
    { "id": "T1046", "name": "Network service discovery", "sev": "MEDIUM", "tactic": "Discovery", "n": 1876, "ips": 7, "countries": 6, "ago": "2m ago",
      "read": "Mapping what's listening. Usually the step before an exploit.",
      "members": [ { "ip": "71.6.232.28", "c": "United States", "n": 402, "ago": "2m" }, { "ip": "162.142.125.8", "c": "United States", "n": 311, "ago": "8m" } ] },
    { "id": "T1105", "name": "Ingress tool transfer", "sev": "MEDIUM", "tactic": "Command and control", "n": 964, "ips": 2, "countries": 2, "ago": "18m ago",
      "read": "Something tried to pull a second-stage binary onto the host.",
      "members": [ { "ip": "45.9.148.12", "c": "Netherlands", "n": 610, "ago": "18m" }, { "ip": "185.220.101.9", "c": "Germany", "n": 354, "ago": "26m" } ] },
    { "id": "T1133", "name": "External remote services", "sev": "MEDIUM", "tactic": "Initial access", "n": 742, "ips": 4, "countries": 4, "ago": "24m ago",
      "read": "RDP and VPN endpoints being tested for a way in.",
      "members": [ { "ip": "103.71.20.4", "c": "Viet Nam", "n": 288, "ago": "24m" }, { "ip": "77.72.5.234", "c": "United Kingdom", "n": 190, "ago": "31m" } ] },
    { "id": "T1595", "name": "Active scanning", "sev": "MEDIUM", "tactic": "Reconnaissance", "n": 690, "ips": 9, "countries": 7, "ago": "1m ago",
      "read": "Background internet weather. Worth counting, not chasing.",
      "members": [ { "ip": "162.142.125.8", "c": "United States", "n": 240, "ago": "1m" }, { "ip": "89.248.165.31", "c": "Netherlands", "n": 180, "ago": "5m" } ] },
    { "id": "T1071", "name": "Application layer protocol", "sev": "MEDIUM", "tactic": "Command and control", "n": 431, "ips": 2, "countries": 2, "ago": "37m ago",
      "read": "Beacon-shaped traffic hiding inside ordinary HTTP.",
      "members": [ { "ip": "20.65.224.144", "c": "United States", "n": 260, "ago": "37m" }, { "ip": "185.220.101.9", "c": "Germany", "n": 171, "ago": "44m" } ] }
  ],

  "origins": [
    { "name": "United States", "cc": "US", "coord": [-77.0, 38.9], "w": 26 },
    { "name": "Belgium", "cc": "BE", "coord": [4.4, 50.8], "w": 17 },
    { "name": "United Kingdom", "cc": "GB", "coord": [-0.1, 51.5], "w": 12 },
    { "name": "Türkiye", "cc": "TR", "coord": [32.9, 39.9], "w": 10 },
    { "name": "Netherlands", "cc": "NL", "coord": [4.9, 52.4], "w": 9 },
    { "name": "China", "cc": "CN", "coord": [116.4, 39.9], "w": 8 },
    { "name": "Russia", "cc": "RU", "coord": [37.6, 55.8], "w": 7 },
    { "name": "Brazil", "cc": "BR", "coord": [-46.6, -23.5], "w": 5 },
    { "name": "India", "cc": "IN", "coord": [77.2, 28.6], "w": 3 },
    { "name": "Viet Nam", "cc": "VN", "coord": [105.8, 21.0], "w": 3 }
  ],

  "cases": [
    {
      "id": "CASE-2026-0817", "date": "17 Aug 2026", "sev": "CRITICAL", "status": "open", "window": "00:00 – 04:45 UTC", "dur": "4h 45m", "confidence": "High",
      "happened": "Seven addresses hit the honeypot inside the same second and kept going for four and three-quarter hours. Six of them ran the same public-facing exploit — 406 attempts between them, all with an identical request signature. The seventh spent the whole window on something different: 174 attempts against Windows admin shares, which is what you do after you are already inside a network, not before.",
      "matters": "Two behaviours running in parallel, starting together, is not six strangers who happened to pick the same afternoon. It reads as one automated framework testing the way in and the way sideways at once. The lateral-movement half is the part that would hurt: on a real network those attempts would be looking for a second machine to land on.",
      "next": "Preserve the honeypot image before anything is cleaned up. Take the SMB source address and search your production logs for the same pattern over the past 30 days. Block all seven addresses at the perimeter, then confirm which public-facing service the 406 attempts were aimed at and whether you run it.",
      "phases": [
        { "t": "00:00:01", "label": "Coordinated arrival", "body": "All seven addresses connect within one second.", "tech": "T1595", "sev": "MEDIUM" },
        { "t": "00:04:12", "label": "Exploitation begins", "body": "406 attempts against the public-facing application.", "tech": "T1190", "sev": "HIGH" },
        { "t": "00:04:19", "label": "Lateral movement, in parallel", "body": "174 attempts against SMB / Windows admin shares.", "tech": "T1021.002", "sev": "CRITICAL" },
        { "t": "04:45:03", "label": "Everything stops at once", "body": "All seven sources go quiet in the same minute.", "tech": null, "sev": "MEDIUM" }
      ],
      "events": [
        { "sev": "CRITICAL", "ip": "20.65.224.144", "tech": "SMB / Windows admin shares", "id": "T1021.002", "n": 174 },
        { "sev": "HIGH", "ip": "34.78.74.222", "tech": "Exploit public-facing application", "id": "T1190", "n": 116 },
        { "sev": "HIGH", "ip": "34.77.48.240", "tech": "Exploit public-facing application", "id": "T1190", "n": 58 },
        { "sev": "HIGH", "ip": "180.181.251.100", "tech": "Exploit public-facing application", "id": "T1190", "n": 58 },
        { "sev": "HIGH", "ip": "71.6.232.28", "tech": "Exploit public-facing application", "id": "T1190", "n": 58 },
        { "sev": "MEDIUM", "ip": "77.72.5.234", "tech": "Exploit public-facing application", "id": "T1190", "n": 58 },
        { "sev": "MEDIUM", "ip": "94.154.43.66", "tech": "Exploit public-facing application", "id": "T1190", "n": 58 }
      ]
    },
    {
      "id": "CASE-2026-0816", "date": "16 Aug 2026", "sev": "CRITICAL", "status": "open", "window": "00:00 – 23:59 UTC", "dur": "24h", "confidence": "High",
      "happened": "A full day of steady, evenly spaced exploitation attempts — 2,880 events with almost no variation in timing. Four techniques appear, but 68% of the volume is a single public-facing exploit repeated on a fixed interval against the node.",
      "matters": "Machine-paced, evenly distributed traffic is scanning infrastructure, not a person. It matters less for what it did than for what it proves: anything you expose is found and retried continuously, without anyone choosing you.",
      "next": "No urgent action on the honeypot. Use this case as the baseline for what background exploitation pressure looks like, and compare your own edge logs against the same 24-hour shape.",
      "phases": [
        { "t": "00:00", "label": "Steady state begins", "body": "120 events an hour, no bursts.", "tech": "T1190", "sev": "HIGH" },
        { "t": "09:30", "label": "Second technique appears", "body": "Brute force added against the same node.", "tech": "T1110", "sev": "MEDIUM" },
        { "t": "18:10", "label": "Credential reuse", "body": "Valid-account attempts using previously seen passwords.", "tech": "T1078", "sev": "HIGH" },
        { "t": "23:59", "label": "Window closes", "body": "Volume unchanged. Campaign still running.", "tech": null, "sev": "MEDIUM" }
      ],
      "events": [
        { "sev": "HIGH", "ip": "34.78.74.222", "tech": "Exploit public-facing application", "id": "T1190", "n": 1180 },
        { "sev": "HIGH", "ip": "71.6.232.28", "tech": "Exploit public-facing application", "id": "T1190", "n": 780 },
        { "sev": "MEDIUM", "ip": "77.72.5.234", "tech": "Brute force", "id": "T1110", "n": 460 },
        { "sev": "HIGH", "ip": "94.154.43.66", "tech": "Valid accounts", "id": "T1078", "n": 300 },
        { "sev": "MEDIUM", "ip": "103.71.20.4", "tech": "Active scanning", "id": "T1595", "n": 160 }
      ]
    },
    {
      "id": "CASE-2026-0815", "date": "15 Aug 2026", "sev": "HIGH", "status": "resolved", "window": "02:10 – 06:40 UTC", "dur": "4h 30m", "confidence": "Medium",
      "happened": "Four addresses from four countries ran a password-guessing campaign against the same account name for four and a half hours, then stopped. No exploitation attempts accompanied it.",
      "matters": "Brute force alone is noise — until the account name is one of yours. The name used here appears in a public breach list, which is how the attacker chose it.",
      "next": "Closed. Recommendation issued: check the same account name across your estate and confirm multi-factor authentication is enforced on it.",
      "phases": [
        { "t": "02:10", "label": "First attempts", "body": "Two addresses, one account name.", "tech": "T1110", "sev": "MEDIUM" },
        { "t": "03:55", "label": "Volume triples", "body": "Two more addresses join with the same wordlist.", "tech": "T1110", "sev": "HIGH" },
        { "t": "06:40", "label": "Campaign abandoned", "body": "No successful authentication at any point.", "tech": null, "sev": "MEDIUM" }
      ],
      "events": [
        { "sev": "HIGH", "ip": "77.72.5.234", "tech": "Brute force", "id": "T1110", "n": 1120 },
        { "sev": "HIGH", "ip": "94.154.43.66", "tech": "Brute force", "id": "T1110", "n": 890 },
        { "sev": "MEDIUM", "ip": "45.9.148.12", "tech": "Brute force", "id": "T1110", "n": 480 },
        { "sev": "MEDIUM", "ip": "103.71.20.4", "tech": "Valid accounts", "id": "T1078", "n": 370 }
      ]
    },
    {
      "id": "CASE-2026-0814", "date": "14 Aug 2026", "sev": "HIGH", "status": "resolved", "window": "01:00 – 23:00 UTC", "dur": "22h", "confidence": "Medium",
      "happened": "Scanning-led day: reconnaissance against the node with a short exploitation burst in the evening.",
      "matters": "The recon fingerprint matches the 17 Aug campaign, three days later — the same framework was mapping targets before it committed.",
      "next": "Closed and linked to CASE-2026-0817 as an earlier stage of the same activity.",
      "phases": [
        { "t": "01:00", "label": "Broad scanning", "body": "Service discovery against the node.", "tech": "T1046", "sev": "MEDIUM" },
        { "t": "19:40", "label": "Short exploitation burst", "body": "42 minutes of public-facing exploit attempts.", "tech": "T1190", "sev": "HIGH" }
      ],
      "events": [
        { "sev": "MEDIUM", "ip": "162.142.125.8", "tech": "Network service discovery", "id": "T1046", "n": 1400 },
        { "sev": "HIGH", "ip": "34.78.74.222", "tech": "Exploit public-facing application", "id": "T1190", "n": 960 }
      ]
    },
    {
      "id": "CASE-2026-0813", "date": "13 Aug 2026", "sev": "MEDIUM", "status": "resolved", "window": "00:00 – 23:59 UTC", "dur": "24h", "confidence": "High",
      "happened": "Uniform background scanning for the full day, single technique, two sources.",
      "matters": "This is the floor — what any exposed machine receives whether or not anyone is interested in it.",
      "next": "Closed. Retained as the quiet-day baseline for comparison.",
      "phases": [
        { "t": "00:00", "label": "Background scanning", "body": "Even pacing, no escalation at any point.", "tech": "T1595", "sev": "MEDIUM" }
      ],
      "events": [
        { "sev": "MEDIUM", "ip": "89.248.165.31", "tech": "Active scanning", "id": "T1595", "n": 1600 },
        { "sev": "MEDIUM", "ip": "162.142.125.8", "tech": "Active scanning", "id": "T1595", "n": 1280 }
      ]
    }
  ],

  "frameworks": [
    { "key": "attack", "name": "MITRE ATT&CK", "sub": "Enterprise · {NTECHDB} techniques",
      "scope": "This assessment covers {NODE}, observed over 24 hours, mapped against MITRE ATT&CK Enterprise.",
      "controls": [
        { "id": "T1190", "name": "Exploit public-facing application", "tactic": "Initial access", "from": "T1190", "line": "Exploitation of a public-facing application was observed {T1190} times from {T1190.ips} address(es) across {T1190.countries} countr(y/ies) in the last 24 hours." },
        { "id": "T1021.002", "name": "SMB / Windows admin shares", "tactic": "Lateral movement", "from": "T1021.002", "line": "Lateral movement via Windows admin shares was observed {T1021.002} times from a single address, indicating post-compromise behaviour rather than initial probing." },
        { "id": "T1110", "name": "Brute force", "tactic": "Credential access", "from": "T1110", "line": "Credential brute force was observed {T1110} times in the last 24 hours." },
        { "id": "T1078", "name": "Valid accounts", "tactic": "Persistence", "from": "T1078", "line": "Attempts to reuse valid credentials were observed {T1078} times in the last 24 hours." },
        { "id": "T1046", "name": "Network service discovery", "tactic": "Discovery", "from": "T1046", "line": "{T1046} network service discovery events were observed in the last 24 hours — mapping what is listening, usually the step before an exploit." },
        { "id": "T1105", "name": "Ingress tool transfer", "tactic": "Command and control", "from": "T1105", "line": "Second-stage payload retrieval (ingress tool transfer) was attempted {T1105} times in the last 24 hours." },
        { "id": "T1566", "name": "Phishing", "tactic": "Initial access", "from": null, "line": "No phishing activity is observable from a honeypot of this type; assess separately." }
      ] },
    { "key": "e8", "name": "Essential Eight", "sub": "ACSC · maturity level 2 target",
      "scope": "This assessment maps 24 hours of honeypot evidence from {NODE} to the ACSC Essential Eight, assessed against maturity level 2.",
      "controls": [
        { "id": "E8", "name": "Application control", "tactic": "Mitigation strategy", "from": "T1105", "line": "{T1105} second-stage binary retrieval attempt(s) were observed; application control would prevent execution if retrieval succeeded." },
        { "id": "E8", "name": "Patch applications", "tactic": "Mitigation strategy", "from": "T1190", "line": "{T1190} exploitation attempts targeted a public-facing application, making application patching the single highest-value control for this exposure." },
        { "id": "E8", "name": "Configure Microsoft Office macro settings", "tactic": "Mitigation strategy", "from": null, "line": "Not observable from network-facing honeypot evidence; assess from endpoint telemetry." },
        { "id": "E8", "name": "User application hardening", "tactic": "Mitigation strategy", "from": null, "line": "Not observable from this evidence source; assess from browser and endpoint configuration." },
        { "id": "E8", "name": "Restrict administrative privileges", "tactic": "Mitigation strategy", "from": "T1021.002", "line": "Admin-share access attempts ({T1021.002}) indicate privilege restriction is the controlling factor once an attacker is inside." },
        { "id": "E8", "name": "Patch operating systems", "tactic": "Mitigation strategy", "from": "T1021.002", "line": "SMB service abuse ({T1021.002} attempts) maps directly to operating system patch currency for exposed hosts." },
        { "id": "E8", "name": "Multi-factor authentication", "tactic": "Mitigation strategy", "from": "CRED", "line": "{CRED} credential-based attempts were recorded; multi-factor authentication would neutralise every one of them." },
        { "id": "E8", "name": "Regular backups", "tactic": "Mitigation strategy", "from": null, "line": "Not observable from this evidence source; lateral movement pressure ({T1021.002} SMB attempts) makes restore testing a stated recommendation." }
      ] },
    { "key": "nist", "name": "NIST CSF 2.0", "sub": "6 functions · 22 categories",
      "scope": "This assessment expresses 24 hours of honeypot evidence from {NODE} against the NIST Cybersecurity Framework 2.0 functions.",
      "controls": [
        { "id": "ID.RA", "name": "Risk assessment", "tactic": "Identify", "from": "NTECH", "line": "{NTECH} distinct techniques observed in 24 hours provide a measured, current threat profile for the exposed estate." },
        { "id": "PR.PS", "name": "Platform security", "tactic": "Protect", "from": "T1190", "line": "Exploitation pressure against a public-facing platform dominates the observed activity ({T1190} attempts)." },
        { "id": "PR.AA", "name": "Identity management, authentication and access control", "tactic": "Protect", "from": "CRED", "line": "{CRED} authentication-based attempts were recorded against a single account identity." },
        { "id": "DE.CM", "name": "Continuous monitoring", "tactic": "Detect", "from": "TOTAL24", "line": "{TOTAL24} raw events were collected and triaged continuously in the last 24 hours." },
        { "id": "DE.AE", "name": "Adverse event analysis", "tactic": "Detect", "from": null, "line": "{IPS24} distinct attacker addresses in the last 24 hours were collapsed into {NTECH} technique categories rather than treated as separate incidents." },
        { "id": "RS.AN", "name": "Incident analysis", "tactic": "Respond", "from": "NCASES", "line": "{NCASES} investigations were opened; each carries a written analysis and a recommended next step." },
        { "id": "RC.RP", "name": "Incident recovery plan execution", "tactic": "Recover", "from": null, "line": "Not exercised during this window; recommend a restore test given observed lateral movement." },
        { "id": "GV.RM", "name": "Risk management strategy", "tactic": "Govern", "from": null, "line": "Governance artefacts sit outside this evidence source; supply separately for a complete assessment." }
      ] },
    { "key": "iso", "name": "ISO/IEC 27001", "sub": "Annex A · 2022 controls",
      "scope": "This assessment references ISO/IEC 27001:2022 Annex A controls supported by 24 hours of honeypot evidence from {NODE}.",
      "controls": [
        { "id": "A.8.8", "name": "Management of technical vulnerabilities", "tactic": "Technological", "from": "T1190", "line": "Sustained exploitation attempts against an exposed service demonstrate the operational need for vulnerability management ({T1190} attempts in 24 hours)." },
        { "id": "A.8.5", "name": "Secure authentication", "tactic": "Technological", "from": "CRED", "line": "{CRED} authentication attempts against one account name evidence the requirement for strong, multi-factor authentication." },
        { "id": "A.8.16", "name": "Monitoring activities", "tactic": "Technological", "from": "TOTAL24", "line": "Continuous monitoring captured and classified {TOTAL24} events with full evidential traceability." },
        { "id": "A.8.20", "name": "Networks security", "tactic": "Technological", "from": "T1021.002", "line": "Lateral movement attempts across SMB support network segmentation and egress control requirements." },
        { "id": "A.5.7", "name": "Threat intelligence", "tactic": "Organisational", "from": "NTECH", "line": "First-party threat intelligence was produced from {NTECH} observed techniques and {NCOUNTRIES} source countries." },
        { "id": "A.5.24", "name": "Information security incident management planning and preparation", "tactic": "Organisational", "from": "NCASES", "line": "{NCASES} incidents were managed end to end in the platform; the governing plan document is required to close this control." },
        { "id": "A.8.13", "name": "Information backup", "tactic": "Technological", "from": null, "line": "Not observable from this evidence source; supply backup and restore test records." }
      ] }
  ]
} /* DATA_END */;
