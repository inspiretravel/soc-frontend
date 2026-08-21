/* iPattern Threat Detector — canonical top-level figures.
 *
 * These two numbers cannot be derived from the tables in data.js, so PS
 * supplies them from the live database. While a value is null the site shows
 * a visible "[PS: fill]" marker and check_invariants.py FAILS the build, so a
 * placeholder can never ship by accident.
 *
 * INV1: allTimeTotal must be >= the 24h total (sum of DATA.queue[].n).
 */
window.FIGURES = /* FIGURES_BEGIN */ {
  "allTimeTotal": 1212,
  "uniqueIps24h": 81
} /* FIGURES_END */;
