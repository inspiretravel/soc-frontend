/* CyberTriageAI — runtime configuration (no secrets here, ever).
 * apiUrl: the read-only public feed. Same-origin path works when the static site
 * is served by the same nginx as the Flask app (Option B). For Cloudflare Pages
 * (Option A) set the full https://api.<domain>/api/public/attacks URL — PS confirms.
 * Set to "" to force the built-in static sample (never fetch). */
window.CONFIG = { apiUrl: "/api/public/attacks", fetchTimeoutMs: 5000 };
