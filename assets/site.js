/* CyberTriageAI — shared helpers. No framework, no innerHTML.
 *
 * Every piece of data on the site (IPs, country names, technique names, case
 * prose) is written into the page through `el()` / `textContent`, so a value
 * that later arrives from /api/public/attacks can never be interpreted as HTML.
 */
(function () {
  "use strict";

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

  /* ---------- derived statistics (computed once, used everywhere) ------- */
  function sum(arr, f) { return arr.reduce(function (s, x) { return s + (f ? f(x) : x); }, 0); }
  function uniq(arr) { return arr.filter(function (x, i) { return arr.indexOf(x) === i; }); }

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
    out.findings = findings; out.ips = ips; out.techniques = techniques;
    return out;
  });
  var openCases = cases.filter(function (c) { return c.status === "open"; }).length;

  function queueN(id) { var q = queue.filter(function (x) { return x.id === id; })[0]; return q ? q.n : 0; }
  var tokens = {
    "TOTAL24": total24, "NTECH": queue.length, "NCASES": cases.length, "NCOUNTRIES": D.origins.length,
    "NTECHDB": D.mitreTechniqueCount, "CRED": queueN("T1110") + queueN("T1078"), "NODE": D.node
  };
  queue.forEach(function (q) { tokens[q.id] = q.n; });
  // Resolve a "{TOKEN}" template into text; numbers are formatted.
  function fill(s) {
    return String(s).replace(/\{([A-Z0-9.]+)\}/g, function (_, k) {
      var v = tokens[k]; if (v === undefined) return "{" + k + "}";
      return typeof v === "number" ? fmt(v) : v;
    });
  }
  function tokenValue(k) { return k ? tokens[k] : undefined; }

  var STATS = {
    queue: queue, total24: total24, bySev: bySev, byTactic: byTactic, tacticsTouched: tacticsTouched,
    categories: queue.length, cases: cases, openCases: openCases, allTime: F.allTimeTotal, uniqueIps24h: F.uniqueIps24h,
    critical24: bySev.CRITICAL
  };

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
  function demoTag(text) { return el("span", { className: "demo-tag", title: "Demo data — not a live feed yet" }, text || "demo data"); }

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
    embed: embed, DISCLAIMER: DISCLAIMER, RM: window.matchMedia("(prefers-reduced-motion: reduce)").matches
  };
})();
