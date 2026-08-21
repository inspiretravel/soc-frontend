/* iPattern Threat Detector — runtime configuration (no secrets here, ever).
 * apiUrl: the read-only public feed. Same-origin path works when the static site
 * is served by the same nginx as the Flask app (Option B). For Cloudflare Pages
 * (Option A) set the full https://api.<domain>/api/public/attacks URL — PS confirms.
 * Set to "" to force the built-in static sample (never fetch). */
/* fetchTimeoutMs: 5s was too tight. The landing page requests this feed while the
 * browser is also pulling d3, topojson, the 394 KB world atlas and an iframe, so a
 * slow connection aborted the fetch and the page fell back to built-in sample
 * figures — while its own map iframe, requested moments later, showed real data.
 * Two contradictory numbers on one screen. */
window.CONFIG = { apiUrl: "/api/public/attacks", fetchTimeoutMs: 15000 };
