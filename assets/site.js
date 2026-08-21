/* CyberTriageAI — shared helpers. No framework; DOM is built with createElement + textContent only.
 *
 * Every piece of data on the site (IPs, country names, technique names, case
 * prose) is written into the page through `el()` / `textContent`, so a value
 * that later arrives from /api/public/attacks can never be interpreted as HTML.
 */
(function () {
  "use strict";

  // D / F start as the built-in static sample (assets/data.js, assets/figures.js) and are
  // replaced by the live feed inside ready() when /api/public/attacks answers.
  var D = window.DATA;
  var F = window.FIGURES || {};

  /* ---------- DOM builder ---------------------------------------------- */
  // el("div", {className:"x", style:"color:red", "data-i":"1"}, "text", childNode, [more])
  // Strings become text nodes (escaped by construction). Attributes are set
  // with setAttribute except for a small allow-list of properties.
  function el(tag, attrs) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "className") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "onclick") node.addEventListener("click", v);
        else if (k === "onmouseenter") node.addEventListener("mouseenter", v);
        else if (k === "onkeydown") node.addEventListener("keydown", v);
        else node.setAttribute(k, v === true ? "" : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) append(node, arguments[i]);
    return node;
  }
  function append(parent, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(parent, c); }); return; }
    if (typeof child === "string" || typeof child === "number") { parent.appendChild(document.createTextNode(String(child))); return; }
    parent.appendChild(child);
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function replace(node) { clear(node); for (var i = 1; i < arguments.length; i++) append(node, arguments[i]); return node; }
  function $(id) { return document.getElementById(id); }

  /* ---------- formatting ------------------------------------------------ */
  function fmt(n) { return Number(n).toLocaleString("en-US"); }
  // Figures that PS must supply render as a visible marker until filled.
  function fig(v) { return (typeof v === "number") ? fmt(v) : "[PS: fill]"; }
  function isFilled(v) { return typeof v === "number"; }

  var SEV = { CRITICAL: "#C4173F", HIGH: "#FFA85C", MEDIUM: "#6BC7F2", LOW: "#8A86A8" };
  var SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  /* ---------- IP masking ------------------------------------------------- */
  // Presentational only: the API and DATA keep full IPs (an approved decision — see
  // docs/FIELD_MAPPING.md); every place the front end DISPLAYS one drops the last octet,
  // so the map's "reported by country, never by address" claim is literally true.
  // "34.78.74.222" -> "34.78.74.xxx"
  function maskIp(ip) {
    var s = String(ip || "");
    var parts = s.split(".");
    if (parts.length !== 4 || !parts.every(function (p) { return /^\d{1,3}$/.test(p); })) return s;
    parts[3] = "xxx";
    return parts.join(".");
  }

  /* ---------- MITRE links ---------------------------------------------- */
  // T1021.002 -> https://attack.mitre.org/techniques/T1021/002/
  function mitreUrl(id) {
    var m = /^T(\d{4})(?:\.(\d{3}))?$/.exec(String(id || ""));
    if (!m) return null;
    return "https://attack.mitre.org/techniques/T" + m[1] + (m[2] ? "/" + m[2] : "") + "/";
  }
  function mitreLink(id, style) {
    var url = mitreUrl(id);
    var a = el(url ? "a" : "span", {
      className: "mono mitre", href: url, target: url ? "_blank" : null, rel: url ? "noopener noreferrer" : null,
      title: url ? "Open " + id + " on attack.mitre.org" : null, style: style || null
    }, id);
    return a;
  }

  /* ---------- derived statistics (computed from D/F, used everywhere) --- */
  function sum(arr, f) { return arr.reduce(function (s, x) { return s + (f ? f(x) : x); }, 0); }
  function uniq(arr) { return arr.filter(function (x, i) { return arr.indexOf(x) === i; }); }

  var STATS = {}, tokens = {};
  function computeStats() {
    var queue = D.queue.slice().sort(function (a, b) {
      var s = SEV_ORDER.indexOf(a.sev) - SEV_ORDER.indexOf(b.sev);
      return s !== 0 ? s : b.n - a.n;
    });
    var total24 = sum(queue, function (q) { return q.n; });
    var bySev = {};
    SEV_ORDER.forEach(function (s) { bySev[s] = sum(queue.filter(function (q) { return q.sev === s; }), function (q) { return q.n; }); });
    var byTactic = {};
    queue.forEach(function (q) { byTactic[q.tactic] = (byTactic[q.tactic] || 0) + q.n; });
    var tacticsTouched = D.tactics.filter(function (t) { return byTactic[t]; }).length;

    var cases = D.cases.map(function (c) {
      var findings = sum(c.events, function (e) { return e.n; });
      var ips = uniq(c.events.map(function (e) { return e.ip; })).length;
      var techniques = uniq(c.events.map(function (e) { return e.id; })).length;
      var out = {}; Object.keys(c).forEach(function (k) { out[k] = c[k]; });
      out.findings = (typeof c.findingCount === "number") ? c.findingCount : findings;   // live: case total; sample: evidence sum
      out.evidenceTotal = findings; out.ips = ips; out.techniques = techniques;
      return out;
    });
    var openCases = (typeof F.openCases === "number") ? F.openCases : cases.filter(function (c) { return c.status === "open"; }).length;
    var critical24 = (typeof F.critical24 === "number") ? F.critical24 : bySev.CRITICAL;

    function queueN(id) { var q = queue.filter(function (x) { return x.id === id; })[0]; return q ? q.n : 0; }
    tokens = {
      "TOTAL24": total24, "NTECH": queue.length, "NCASES": cases.length, "NCOUNTRIES": D.origins.length,
      "NTECHDB": D.mitreTechniqueCount, "CRED": queueN("T1110") + queueN("T1078"), "NODE": D.node,
      "IPS24": (typeof F.uniqueIps24h === "number") ? F.uniqueIps24h : "[PS: fill]"
    };
    queue.forEach(function (q) { tokens[q.id] = q.n; tokens[q.id + ".ips"] = q.ips; tokens[q.id + ".countries"] = q.countries; });

    STATS.queue = queue; STATS.total24 = total24; STATS.bySev = bySev; STATS.byTactic = byTactic;
    STATS.tacticsTouched = tacticsTouched; STATS.categories = queue.length; STATS.cases = cases;
    STATS.openCases = openCases; STATS.allTime = F.allTimeTotal; STATS.uniqueIps24h = F.uniqueIps24h;
    STATS.critical24 = critical24; STATS.aiWrittenCases = (typeof F.aiWrittenCases === "number") ? F.aiWrittenCases : cases.length;
    STATS.buckets5m = D.buckets5m || null; STATS.buckets30m = D.buckets30m || null; STATS.bucketsRange = D.bucketsRange || null; STATS.recent = D.recent || null;
    STATS.node = D.node; STATS.nodeShort = D.nodeShort; STATS.nodeCoord = D.nodeCoord;
    return STATS;
  }
  // Resolve a "{TOKEN}" template into text; numbers are formatted.
  function fill(s) {
    return String(s).replace(/\{([A-Z0-9.]+(?:\.[a-z]+)?)\}/g, function (_, k) {
      var v = tokens[k]; if (v === undefined) return "{" + k + "}";
      return typeof v === "number" ? fmt(v) : v;
    });
  }
  function tokenValue(k) { return k ? tokens[k] : undefined; }
  computeStats();   // sample stats are available synchronously; ready() recomputes after the fetch

  /* ---------- live feed: fetch → map → fallback ------------------------- */
  // Country centroids for drawing arcs (region-level; not attacker locations).
  var CENTROID = { US: [-98.5, 39.8], BE: [4.5, 50.6], GB: [-2.0, 54.0], TR: [35.2, 39.0], NL: [5.3, 52.2], CN: [104.2, 35.9],
    RU: [90.0, 60.0], BR: [-51.9, -14.2], IN: [78.9, 22.6], VN: [108.3, 14.1], DE: [10.4, 51.2], FR: [2.2, 46.6], KR: [127.8, 36.5],
    JP: [138.3, 36.2], SG: [103.8, 1.35], HK: [114.2, 22.3], TW: [120.9, 23.7], ID: [113.9, -0.8], TH: [100.9, 15.9], PK: [69.3, 30.4],
    BD: [90.4, 23.7], IR: [53.7, 32.4], UA: [31.2, 48.4], PL: [19.1, 51.9], RO: [24.9, 45.9], BG: [25.5, 42.7], IT: [12.6, 41.9],
    ES: [-3.7, 40.5], PT: [-8.2, 39.4], SE: [18.6, 60.1], FI: [25.7, 61.9], NO: [8.5, 60.5], CA: [-106.3, 56.1], MX: [-102.6, 23.6],
    AR: [-63.6, -38.4], CO: [-74.3, 4.6], ZA: [22.9, -30.6], NG: [8.7, 9.1], EG: [30.8, 26.8], AU: [133.8, -25.3], NZ: [174.9, -40.9],
    KZ: [66.9, 48.0], LT: [23.9, 55.2], LV: [24.6, 56.9], EE: [25.0, 58.6], CZ: [15.5, 49.8], HU: [19.5, 47.2], AT: [14.6, 47.5],
    CH: [8.2, 46.8], IE: [-8.2, 53.4], MD: [28.4, 47.4], SC: [55.5, -4.7], PA: [-80.8, 8.5], AE: [53.8, 23.4], SA: [45.1, 23.9] };

  function timeAgo(iso) {
    if (!iso) return "";
    var t = Date.parse(iso); if (isNaN(t)) return "";
    var s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return s + "s ago"; var m = Math.floor(s / 60);
    if (m < 60) return m + "m ago"; var h = Math.floor(m / 60);
    if (h < 48) return h + "h ago"; return Math.floor(h / 24) + "d ago";
  }
  function hhmm(iso) { var d = new Date(iso); return isNaN(d) ? "" : ("0" + d.getUTCHours()).slice(-2) + ":" + ("0" + d.getUTCMinutes()).slice(-2); }
  function hhmmss(iso) { var d = new Date(iso); return isNaN(d) ? "" : hhmm(iso) + ":" + ("0" + d.getUTCSeconds()).slice(-2); }
  function humanDur(a, b) {
    var ms = Date.parse(b) - Date.parse(a); if (isNaN(ms) || ms < 0) return "";
    var m = Math.round(ms / 60000); if (m < 60) return m + "m"; var h = Math.floor(m / 60); return h + "h" + (m % 60 ? " " + (m % 60) + "m" : "");
  }
  function dateLabel(iso) { var d = new Date(iso); return isNaN(d) ? "" : d.getUTCDate() + " " + ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getUTCMonth()] + " " + d.getUTCFullYear(); }

  // Analyst one-liners per technique — authored prose, NOT data (docs/FIELD_MAPPING.md §C).
  var READ = {};
  (window.DATA.queue || []).forEach(function (q) { READ[q.id] = q.read; });

  // Map the API payload (public_api.build_payload) into the page shape data.js uses.
  function mapPayload(p) {
    var sample = window.DATA;
    var out = {
      brand: sample.brand, tactics: sample.tactics, frameworks: sample.frameworks,
      mitreTechniqueCount: (p.figures && p.figures.mitre_technique_count) || sample.mitreTechniqueCount,
      node: "a single honeypot node in " + ((p.node && p.node.label) || sample.nodeShort).replace(/, AU$/, ", Australia"),
      nodeShort: (p.node && p.node.label) || sample.nodeShort, nodeCoord: (p.node && p.node.coord) || sample.nodeCoord,
      queue: (p.queue || []).map(function (q) {
        return { id: q.id, name: q.name, sev: q.sev || "LOW", tactic: q.tactic, n: q.n, ips: q.ips, countries: q.countries,
          ago: timeAgo(q.last_seen), read: READ[q.id] || "", hourly: q.hourly || null,
          members: (q.members || []).map(function (m) { return { ip: m.ip, c: m.country || "", n: m.n, ago: timeAgo(m.last_seen) }; }) };
      }),
      origins: (p.origins || []).map(function (o) { return { name: o.country, cc: o.cc, coord: CENTROID[o.cc] || null, w: Math.round(o.pct), n: o.n }; }),
      cases: (p.cases || []).map(function (c) {
        var s = c.ai_summary;
        return { id: "CASE-" + c.id, title: c.title, date: dateLabel(c.created_at), sev: c.severity || "LOW", status: c.status,
          window: c.first_seen ? hhmm(c.first_seen) + " – " + hhmm(c.last_seen) + " UTC" : "—", dur: humanDur(c.first_seen, c.last_seen),
          confidence: null, findingCount: c.finding_count, source: c.source,
          happened: s ? s.happening : null, matters: s ? s.matters : null, next: s ? s.next : null,
          writtenAtFindings: s ? s.written_at_findings : null,
          phases: (c.phases || []).map(function (ph) {
            return { t: hhmmss(ph.first_seen), label: ph.name || ph.tid, body: fmt(ph.n) + " event" + (ph.n === 1 ? "" : "s") + " from " + ph.ips + " address" + (ph.ips === 1 ? "" : "es"), tech: ph.tid, sev: ph.sev || "LOW" };
          }),
          events: (c.groups || []).map(function (g) { return { sev: g.sev || "LOW", ip: g.ip, tech: g.name, id: g.tid, n: g.n }; }) };
      }),
      buckets5m: p.buckets_5m || null, buckets30m: p.buckets_30m || null, bucketsRange: p.buckets_range || null,
      recent: (p.recent || []).map(function (r) { return { cc: r.cc, coord: CENTROID[r.cc] || null, sev: r.sev, tid: r.tid, at: r.at }; })
    };
    var f = p.figures || {};
    var figs = { allTimeTotal: f.all_time_total, uniqueIps24h: f.unique_ips_24h, critical24: f.critical_24h,
      openCases: f.open_cases, aiWrittenCases: f.ai_written_cases_7d, generatedAt: p.generated_at,
      newestEventAt: f.newest_event_at || null };
    return { data: out, figures: figs };
  }

  var SOURCE = { kind: "sample", generatedAt: null, error: null };
  var readyState = "loading", pending = [];
  function finish(kind, err) {
    SOURCE.kind = kind; SOURCE.error = err || null; SOURCE.generatedAt = F.generatedAt || null;
    computeStats(); readyState = "done";
    pending.splice(0).forEach(function (cb) { try { cb(); } catch (e) { if (window.console) console.error(e); } });
  }
  function ready(cb) { if (readyState === "done") cb(); else pending.push(cb); }

  /* ---------- range selection: day / week / month / all --------------------
   * Every page starts on "day" (byte-identical to the site's original,
   * pre-range behaviour). Switching ranges re-fetches ?range=X, remaps and
   * recomputes STATS, then notifies whatever the current page registered via
   * onRangeChange — it does NOT fall back to sample data on a failed range
   * switch (only the very first load does that), so a transient network blip
   * after the page already has live data just leaves the last good view up. */
  var CURRENT_RANGE = "day", rangeListeners = [], rangeBusy = false, initialRetried = false;
  function fetchRange(range, isInitial) {
    var cfg = window.CONFIG || {}, base = cfg.apiUrl;
    if (!base || typeof fetch !== "function") {
      if (isInitial) finish("sample", "no api configured");
      return Promise.resolve();
    }
    var url = base + (base.indexOf("?") >= 0 ? "&" : "?") + "range=" + encodeURIComponent(range);
    var ctl = (typeof AbortController === "function") ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, cfg.fetchTimeoutMs || 5000);
    return fetch(url, { method: "GET", credentials: "omit", mode: "cors", cache: "default", signal: ctl ? ctl.signal : undefined })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (p) {
        clearTimeout(timer);
        if (!p || !Array.isArray(p.queue) || !p.figures) throw new Error("bad payload");
        var m = mapPayload(p); D = m.data; F = m.figures; CURRENT_RANGE = p.range || range;
        if (isInitial) {
          finish("live");
        } else {
          SOURCE.kind = "live"; SOURCE.error = null; SOURCE.generatedAt = F.generatedAt || null;
          computeStats();
          rangeListeners.forEach(function (cb) { try { cb(CURRENT_RANGE); } catch (e) { if (window.console) console.error(e); } });
        }
      })
      .catch(function (e) {
        clearTimeout(timer);
        if (!isInitial) { if (window.console) console.error("range switch failed:", e); return; }
        // The landing page fires this request while the browser is also pulling the
        // globe libraries, the world atlas and an iframe — enough contention to blow
        // a short timeout on a slow connection. Falling back on the FIRST failure
        // meant the page showed built-in sample figures while the very same page's
        // map iframe, requested moments later, got real data: two contradictory
        // numbers on one screen. Retry once before giving up.
        if (!initialRetried) {
          initialRetried = true;
          if (window.console) console.warn("live feed attempt 1 failed (" + (e && e.message || e) + ") — retrying once");
          setTimeout(function () { fetchRange(range, true); }, 900);
          return;
        }
        finish("sample", String(e && e.message || e));
      });
  }
  fetchRange("day", true);   // initial load — identical request/behaviour to the original fetchLive()

  function setRange(range) {
    if (range === CURRENT_RANGE || rangeBusy) return Promise.resolve();
    rangeBusy = true;
    return fetchRange(range, false).then(function () { rangeBusy = false; }, function () { rangeBusy = false; });
  }
  function onRangeChange(cb) { rangeListeners.push(cb); }
  function currentRange() { return CURRENT_RANGE; }

  var RANGE_LABELS = [["day", "Day"], ["week", "Week"], ["month", "Month"], ["all", "All"]];
  // Builds a fresh button group each call — pages rebuild it (via onRangeChange)
  // so the pressed state always reflects the range just switched to.
  function rangeSelector(current) {
    return el("div", { className: "rangesel", role: "group", "aria-label": "Time range" },
      RANGE_LABELS.map(function (r) {
        return el("button", { type: "button", "aria-pressed": r[0] === current ? "true" : "false",
          onclick: function () { setRange(r[0]); } }, r[1]);
      }));
  }

  // How old the newest honeypot event is, in minutes — null when unknown.
  // "refreshed 20s ago" only means the API answered; it says nothing about whether
  // the honeypot is still feeding it. Two multi-day stalls served perfectly fresh
  // responses full of stale data, so freshness of the DATA is tracked separately.
  var STALE_AFTER_MIN = 60;
  function dataAgeMinutes() {
    var iso = F.newestEventAt;
    if (!iso) return null;
    var t = Date.parse(iso);
    if (isNaN(t)) return null;
    return Math.max(0, (Date.now() - t) / 60000);
  }
  function isStale() { var m = dataAgeMinutes(); return m !== null && m > STALE_AFTER_MIN; }

  function sourceBadge() {
    if (SOURCE.kind === "live") {
      // Live API, but no new honeypot data for a while — say so plainly rather than
      // showing a green "live" pill over numbers that stopped moving hours ago.
      if (isStale()) {
        var stalePill = el("span", { className: "pill",
          title: "The API is reachable and these numbers are accurate, but no new honeypot event has arrived since " + F.newestEventAt + ". The capture pipeline may have stalled." },
          el("span", { className: "dot", style: "background:#FFA85C;box-shadow:0 0 9px #FFA85C;" }),
          "feed stale · no data for " + timeAgo(F.newestEventAt).replace(" ago", ""));
        stalePill.setAttribute("data-source-badge", "");
        return stalePill;
      }
      var pill = livePill("live · " + (SOURCE.generatedAt ? "refreshed " + timeAgo(SOURCE.generatedAt) : "just now"), "#5FE3B0");
      pill.setAttribute("data-source-badge", "");
      return pill;
    }
    return el("span", { className: "pill", title: "The live feed was not reachable" + (SOURCE.error ? " (" + SOURCE.error + ")" : "") + " — showing the built-in sample." },
      el("span", { className: "dot", style: "background:#FFA85C;box-shadow:0 0 9px #FFA85C;" }), "sample data");
  }
  function isLive() { return SOURCE.kind === "live"; }

  // Keep the pill text current without a page reload. If the data goes stale while
  // the page is open (a stall starting mid-session), the label flips to the warning
  // on its own rather than sitting on a reassuring "live" until someone reloads.
  setInterval(function () {
    if (SOURCE.kind !== "live") return;
    var stale = isStale();
    var label = stale
      ? "feed stale · no data for " + timeAgo(F.newestEventAt).replace(" ago", "")
      : "live · " + (SOURCE.generatedAt ? "refreshed " + timeAgo(SOURCE.generatedAt) : "just now");
    document.querySelectorAll("[data-source-badge]").forEach(function (pill) {
      var textNode = pill.lastChild;
      if (textNode && textNode.nodeType === 3) textNode.textContent = label;
      var dot = pill.firstChild;
      if (dot && dot.style) {
        var c = stale ? "#FFA85C" : "#5FE3B0";
        dot.style.background = c; dot.style.boxShadow = "0 0 9px " + c;
      }
    });
  }, 15000);

  /* ---------- chrome: nav + footer -------------------------------------- */
  var NAV = [
    ["dashboard.html", "Dashboard"], ["attack-map.html", "Attack Map"], ["cases.html", "Cases"],
    ["reference.html", "Reference"], ["about.html", "About"]
  ];
  var DISCLAIMER = "AI-generated triage — portfolio demo. Human review required before action.";

  function logo(size) {
    var s = size || 28;
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("width", Math.round(s * 0.54)); svg.setAttribute("height", Math.round(s * 0.54)); svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("fill", "none"); svg.setAttribute("aria-hidden", "true");
    var p1 = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p1.setAttribute("d", "M12 2.5 20 6v6.2c0 4.9-3.3 8.4-8 9.3-4.7-.9-8-4.4-8-9.3V6l8-3.5Z"); p1.setAttribute("fill", "#fff");
    var p2 = document.createElementNS("http://www.w3.org/2000/svg", "path");
    p2.setAttribute("d", "M8.6 12.2l2.3 2.3 4.5-4.6"); p2.setAttribute("stroke", "#6A2350"); p2.setAttribute("stroke-width", "2"); p2.setAttribute("stroke-linecap", "round"); p2.setAttribute("stroke-linejoin", "round");
    svg.appendChild(p1); svg.appendChild(p2);
    return el("a", { href: "index.html", className: "brand", "aria-label": "CyberTriageAI home" },
      el("span", { className: "brand-mark", style: "width:" + s + "px;height:" + s + "px;" }, svg),
      el("span", { className: "brand-name" }, "CyberTriage", el("span", { style: "color:#F2547D;" }, "AI")));
  }

  function renderHeader(active, statusNode) {
    var host = $("site-header"); if (!host) return;
    var nav = el("nav", { "aria-label": "Primary" }, NAV.map(function (n) {
      return el("a", { className: "tab", href: n[0], "aria-current": active === n[0] ? "page" : null, "data-active": active === n[0] ? "" : null }, n[1]);
    }));
    replace(host, el("div", { className: "hdr-left" }, logo(28), nav), el("div", { className: "hdr-right" }, statusNode || null));
  }

  function renderFooter() {
    var host = $("site-footer"); if (!host) return;
    replace(host,
      el("div", { className: "foot-inner" },
        el("div", { className: "foot-brand" }, logo(24), el("span", { className: "foot-tag" }, "Real honeypot. Real attacks. Plain English.")),
        el("nav", { className: "foot-links", "aria-label": "Footer" }, NAV.map(function (n) { return el("a", { href: n[0] }, n[1]); }),
          el("span", { className: "foot-copy" }, "© 2026")),
        el("p", { className: "disclaimer", role: "note" }, DISCLAIMER)));
  }

  function livePill(text, color) {
    return el("span", { className: "pill" }, el("span", { className: "dot", style: "background:" + (color || "#5FE3B0") + ";box-shadow:0 0 9px " + (color || "#5FE3B0") + ";" }), text);
  }
  function demoTag(text, title) { return el("span", { className: "demo-tag", title: title || null }, text || "demo data"); }

  /* ---------- embedded (iframe) mode ------------------------------------ */
  // When a subpage is shown inside index.html's "Inside the tool" frame we hide
  // the chrome and report our height so the parent can size the frame.
  function embed(type, measureEl) {
    if (window.self === window.top) return false;
    document.documentElement.setAttribute("data-embedded", "");
    var report = function () {
      var h = Math.ceil((measureEl || document.body).getBoundingClientRect().height + 40);
      parent.postMessage({ type: type, height: h }, "*");
    };
    window.addEventListener("load", report);
    if (window.ResizeObserver) new ResizeObserver(report).observe(measureEl || document.body);
    setTimeout(report, 700);
    return true;
  }

  window.Site = {
    el: el, append: append, clear: clear, replace: replace, $: $, fmt: fmt, fig: fig, isFilled: isFilled,
    SEV: SEV, SEV_ORDER: SEV_ORDER, mitreUrl: mitreUrl, mitreLink: mitreLink, fill: fill, tokenValue: tokenValue,
    STATS: STATS, renderHeader: renderHeader, renderFooter: renderFooter, logo: logo, livePill: livePill, demoTag: demoTag,
    embed: embed, DISCLAIMER: DISCLAIMER, RM: window.matchMedia("(prefers-reduced-motion: reduce)").matches,
    ready: ready, sourceBadge: sourceBadge, isLive: isLive, timeAgo: timeAgo, maskIp: maskIp, data: function () { return D; }, figures: function () { return F; },
    setRange: setRange, onRangeChange: onRangeChange, currentRange: currentRange, rangeSelector: rangeSelector
  };
})();
