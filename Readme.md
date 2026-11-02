# ISL_Project
 BrowserCap — Playwright inspector for fake / misleading download buttons.
 *
 * Collects:
 *   1. Download-looking elements
 *   2. Displayed text vs actual destination URLs
 *   3. Unexpected tabs / pop-ups
 *   4. Actual download events + navigation / redirect behaviour
 *
 * Writes JSON for the Python classifier (default: browser_features.json).
 *
 * Usage:
 *   node BrowserCap.js [url] [--click] [--out path]
 *
 * --click   Actively click candidate buttons (only on pages you control)
 * --out     Output JSON path (default browser_features.json)
FileCap - Offline PCAP feature extractor for website risk scoring.

Pipeline:
  1. Parse DNS answers → domain_to_ips / ip_to_domains
  2. Parse HTTP  → cleartext flag, redirect counts, Host header
  3. Parse TLS   → SNI hostname, fatal alert counts (HTTPS stand-in)
  4. Compare Host/SNI + server IP against DNS maps → Hostname_mismatch
  5. classify() → per-domain risk scores
* Usage:
* python FileCap.py [1 to save output else 0 as default] [output_file]

classify.py Usage :- python classify.py [json_file]