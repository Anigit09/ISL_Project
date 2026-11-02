

from __future__ import annotations

import json
from pathlib import Path


HTTP_RISK = 0.05
REDIRECT_RISK = 0.15
TLS_FAILURE_RISK = 0.15
HOSTNAME_MISMATCH_RISK = 0.15


EXTERNAL_DOWNLOAD_DEST_RISK = 0.10  
POPUP_RISK = 0.15
FAKE_DOWNLOAD_SIGNAL_RISK = 0.20

NO_REAL_DOWNLOAD_RISK = 0.05


def score_domain(features: dict) -> float:
    
    risk = 0.0

  
    if features.get("http"):
        risk += HTTP_RISK


    if features.get("Redirects", 0) > 2:
        risk += REDIRECT_RISK

   
    if features.get("Hostname_mismatch"):
        risk += HOSTNAME_MISMATCH_RISK


    if features.get("tls_failures", 0) > 2:
        risk += TLS_FAILURE_RISK


    external = int(features.get("external_download_destinations", 0) or 0)
    if external:
        risk += min(EXTERNAL_DOWNLOAD_DEST_RISK * external, 0.30)

    if int(features.get("unexpected_popups", 0) or 0) > 0:
        risk += POPUP_RISK

    fake = int(features.get("fake_download_signals", 0) or 0)
    if fake:
        risk += min(FAKE_DOWNLOAD_SIGNAL_RISK * fake, 0.40)


    buttons = int(features.get("download_buttons", 0) or 0)
    actual = int(features.get("actual_downloads", 0) or 0)
    if buttons > 0 and actual == 0:
        risk += NO_REAL_DOWNLOAD_RISK

    return min(risk, 1.0)


def classify(domain_features: dict) -> dict:

    return {
        domain: score_domain(feats)
        for domain, feats in domain_features.items()
        if domain
    }


def features_from_browser_json(data: dict) -> dict:

    domain = data.get("domain") or "unknown"
    return {
        domain: {
            "http": False,
            "Hostname_mismatch": False,
            "Redirects": int(data.get("redirect_count", 0) or 0),
            "tls_failures": 0,
            "download_buttons": int(data.get("download_buttons", 0) or 0),
            "external_download_destinations": int(
                data.get("external_download_destinations", 0) or 0
            ),
            "unexpected_popups": int(data.get("unexpected_popups", 0) or 0),
            "actual_downloads": int(data.get("actual_downloads", 0) or 0),
            "fake_download_signals": int(data.get("fake_download_signals", 0) or 0),
        }
    }


def classify_browser_report(path: str | Path) -> dict:
    
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    features = features_from_browser_json(data)
    return classify(features)


def merge_features(*feature_maps: dict) -> dict:
 
    bool_keys = {"http", "Hostname_mismatch"}
    merged: dict[str, dict] = {}
    for fmap in feature_maps:
        for domain, feats in fmap.items():
            slot = merged.setdefault(domain, {})
            for key, value in feats.items():
                if key in bool_keys:
                    slot[key] = bool(slot.get(key, False) or value)
                elif isinstance(value, (int, float)):
                    slot[key] = max(slot.get(key, 0), value)
                else:
                    slot[key] = value
    return merged


if __name__ == "__main__":
    import sys

    report = Path(sys.argv[1] if len(sys.argv) > 1 else "browser_features.json")
    if not report.is_file():
        raise SystemExit(f"report not found: {report}")
    risks = classify_browser_report(report)
    for domain, risk in risks.items():
        print(f"{domain}: risk={risk:.2f}")
