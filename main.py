"""
Load BrowserCap JSON (and optional FileCap results) into classify.py.

Examples:
  python main.py browser_features.json
  python main.py browser_features.json --pcap-features pcap_features.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from classify import (
    classify,
    classify_browser_report,
    features_from_browser_json,
    merge_features,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score BrowserCap / FileCap features")
    parser.add_argument(
        "browser_json",
        nargs="?",
        default="browser_features.json",
        help="JSON written by BrowserCap.js",
    )
    parser.add_argument(
        "--pcap-features",
        help="Optional JSON {domain: {http, Redirects, ...}} from FileCap",
    )
    args = parser.parse_args()

    browser_path = Path(args.browser_json)
    if not browser_path.is_file():
        raise SystemExit(
            f"missing {browser_path}\n"
            "Run: node BrowserCap.js http://127.0.0.1:8000 --click"
        )

    raw = json.loads(browser_path.read_text(encoding="utf-8"))
    browser_feats = features_from_browser_json(raw)

    if args.pcap_features:
        pcap = json.loads(Path(args.pcap_features).read_text(encoding="utf-8"))
        features = merge_features(pcap, browser_feats)
        risks = classify(features)
    else:
        risks = classify(browser_feats)

    print("BrowserCap summary:")
    for key in (
        "domain",
        "download_buttons",
        "external_download_destinations",
        "unexpected_popups",
        "actual_downloads",
        "fake_download_signals",
    ):
        if key in raw:
            print(f"  {key}: {raw[key]}")

    print("\nRisk scores:")
    for domain, risk in risks.items():
        print(f"  {domain}: {risk:.2f}")


if __name__ == "__main__":
    main()
