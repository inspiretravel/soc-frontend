"""
check_invariants.py — reject the build if the site's numbers can't all be true at once.

Reads assets/data.js and assets/figures.js (the only two places numbers live),
recomputes the same derived figures the pages compute, and enforces:

  INV1  all-time total >= 24h total
  INV2  24h total == sum of category rows            (structural — always true, checked anyway)
  INV3  "What they're trying" == queue counts         (structural — same rows)
  INV4  cases vs categories are separate metrics      (labelled distinctly; both counts printed)
  INV5  per-case narrative counts == evidence sums    (numbers quoted in prose must appear in the table)
  PS    no unfilled placeholder figures
  IDs   every MITRE technique ID is well-formed and links resolve to a real technique
        (checked against the local STIX cache when available)

Run:  python check_invariants.py          -> exit 0 = OK, exit 1 = reject
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
STIX_CACHE = Path(r"C:\Users\PC\Documents\Claude\Projects\AI Cybersecurity project\data\enterprise-attack.json")

def load_js_object(path, begin, end):
    text = path.read_text(encoding="utf-8")
    start = text.index(begin) + len(begin)
    stop = text.index(end)
    return json.loads(text[start:stop])

errors, warns = [], []
def fail(msg): errors.append(msg)
def warn(msg): warns.append(msg)

data = load_js_object(ROOT / "assets" / "data.js", "/* DATA_BEGIN */", "/* DATA_END */")
figs = load_js_object(ROOT / "assets" / "figures.js", "/* FIGURES_BEGIN */", "/* FIGURES_END */")

queue = data["queue"]
total24 = sum(q["n"] for q in queue)
categories = len(queue)
cases = data["cases"]

# ---- PS placeholders -------------------------------------------------------
for k, v in figs.items():
    if not isinstance(v, (int, float)):
        fail(f"PS placeholder unfilled: FIGURES.{k} is {v!r} — supply the live-DB value in assets/figures.js")

# ---- INV1 --------------------------------------------------------------------
all_time = figs.get("allTimeTotal")
if isinstance(all_time, (int, float)):
    if all_time < total24:
        fail(f"INV1: all-time total {all_time:,} < 24h total {total24:,}")

# ---- INV2 / INV3 (structural, but confirm no zero/negative rows) --------------
for q in queue:
    if not isinstance(q["n"], int) or q["n"] <= 0:
        fail(f"INV2: queue row {q['id']} has non-positive count {q['n']!r}")
    for m in q.get("members", []):
        if m["n"] > q["n"]:
            fail(f"INV2: member {m['ip']} ({m['n']}) exceeds its category {q['id']} ({q['n']})")

# ---- INV4 (informational: two different metrics, labelled as such) ------------
open_cases = sum(1 for c in cases if c["status"] == "open")

# ---- INV5: prose numbers must exist in the evidence table --------------------
def numbers_in(text):
    return {int(x.replace(",", "")) for x in re.findall(r"\b\d{1,3}(?:,\d{3})+\b|\b\d{2,}\b", text)}

for c in cases:
    ev_total = sum(e["n"] for e in c["events"])
    ev_ips = {e["ip"] for e in c["events"]}
    ev_tech = {e["id"] for e in c["events"]}
    by_tech = {}
    for e in c["events"]:
        by_tech[e["id"]] = by_tech.get(e["id"], 0) + e["n"]
    allowed = {ev_total, len(ev_ips), len(ev_tech)} | set(by_tech.values()) | {e["n"] for e in c["events"]}
    # percentages of a technique's share are also legitimate
    allowed |= {round(v / ev_total * 100) for v in by_tech.values()}
    # hourly rate over the case window is a legitimate derived figure (e.g. "120 events an hour" for 2,880 / 24h)
    if c["dur"].endswith("h") and c["dur"][:-1].isdigit():
        allowed.add(round(ev_total / int(c["dur"][:-1])))
    prose = " ".join([c["happened"], c["matters"], c["next"]] + [p["body"] for p in c["phases"]])
    prose = re.sub(r"CASE-\d{4}-\d{4}", " ", prose)                       # case IDs are not counts
    prose = re.sub(r"\b\d+\s*(?:minutes?|hours?|days?|seconds?)\b", " ", prose)  # durations are not counts
    for num in numbers_in(prose):
        if num >= 30 and num not in allowed and num < 2000 or (num >= 2000 and num not in allowed and num != 2026):
            fail(f"INV5: {c['id']} prose mentions {num:,} but no evidence figure equals it (evidence total {ev_total:,}; per-technique {by_tech})")
    # word-form counts of addresses
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}
    m = re.search(r"\b(one|two|three|four|five|six|seven|eight|nine|ten) (?:addresses|sources)\b", c["happened"], re.I)
    if m and words[m.group(1).lower()] != len(ev_ips):
        fail(f"INV5: {c['id']} says '{m.group(0)}' but evidence has {len(ev_ips)} distinct IPs")
    m = re.search(r"\b(one|two|three|four|five|six|seven|eight|nine|ten) techniques\b", c["happened"], re.I)
    if m and words[m.group(1).lower()] != len(ev_tech):
        fail(f"INV5: {c['id']} says '{m.group(0)}' but evidence has {len(ev_tech)} distinct techniques")

# ---- MITRE IDs ----------------------------------------------------------------
ids = set()
for q in queue: ids.add(q["id"])
for c in cases:
    for e in c["events"]: ids.add(e["id"])
    for p in c["phases"]:
        if p["tech"]: ids.add(p["tech"])
for f in data["frameworks"]:
    if f["key"] == "attack":
        for ctl in f["controls"]: ids.add(ctl["id"])
bad = [i for i in ids if not re.fullmatch(r"T\d{4}(\.\d{3})?", i)]
for b in bad: fail(f"MITRE: malformed technique ID {b!r}")

if STIX_CACHE.exists():
    stix = json.loads(STIX_CACHE.read_text(encoding="utf-8"))
    real = set()
    for o in stix["objects"]:
        if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    real.add(ref["external_id"])
    for i in sorted(ids):
        if i not in real:
            fail(f"MITRE: {i} not found among {len(real)} active Enterprise techniques in local STIX cache")
    if data["mitreTechniqueCount"] != len(real):
        fail(f"MITRE: DATA.mitreTechniqueCount={data['mitreTechniqueCount']} but STIX cache has {len(real)} active techniques")
else:
    warn("STIX cache not found - technique IDs checked for shape only")

# ---- Essential Eight naming (T1.5) ------------------------------------------
E8 = ["Application control", "Patch applications", "Configure Microsoft Office macro settings", "User application hardening",
      "Restrict administrative privileges", "Patch operating systems", "Multi-factor authentication", "Regular backups"]
e8 = [f for f in data["frameworks"] if f["key"] == "e8"][0]
names = [c["name"] for c in e8["controls"]]
if names != E8:
    fail(f"E8: control names/order differ from ACSC list: {names}")

# ---- report --------------------------------------------------------------------
print(f"24h total (sum of {categories} category rows): {total24:,}")
print(f"all-time total (FIGURES): {all_time!r}")
print(f"cases: {len(cases)} ({open_cases} open)  |  categories: {categories}   <- INV4: distinct metrics, labelled distinctly")
for c in cases:
    print(f"  {c['id']}: evidence total {sum(e['n'] for e in c['events']):,}, {len({e['ip'] for e in c['events']})} IPs, {len({e['id'] for e in c['events']})} techniques")
for w in warns: print("WARN:", w)
if errors:
    print("\nREJECT - %d problem(s):" % len(errors))
    for e in errors: print("  x", e)
    sys.exit(1)
print("\nOK - all invariants hold, no placeholders remain.")
