
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pyshark
import json
from classify import classify

REDIRECT_CODES = {"301", "302", "303", "307", "308"}
HTTP_PORTS = {"80"}
HTTPS_PORTS = {"443"}


def _empty_features() -> dict:
    return {
        "http": False,
        "Hostname_mismatch": False,
        "Redirects": 0,
        "tls_failures": 0,
    }


class FCap:
    def __init__(self, f):
        self.file = str(f)
        self.domain_features: dict[str, dict] = {}

       
        self.domain_to_ips: dict[str, set[str]] = defaultdict(set)
        self.ip_to_domains: dict[str, set[str]] = defaultdict(set)

       
        self.stream_hostname: dict[str, str] = {}
       
        self.observed_destinations: set[tuple[str, str]] = set()

    def get_features(self, domain: str | None) -> dict | None:
        if not domain:
            return None
        domain = domain.rstrip(".").lower()
        if domain not in self.domain_features:
            self.domain_features[domain] = _empty_features()
        return self.domain_features[domain]

    @staticmethod
    def _norm_host(value: str | None) -> str | None:
        if not value:
            return None
        return value.split(":")[0].rstrip(".").lower()

    
    def _process_dns(self, packet) -> None:
        dns = packet.dns
        name = None
        if hasattr(dns, "qry_name") and dns.qry_name:
            name = dns.qry_name
        elif hasattr(dns, "resp_name") and dns.resp_name:
            name = dns.resp_name
        if not name:
            return

        name = self._norm_host(str(name))
        self.get_features(name)

        for attr in ("a", "aaaa"):
            if not hasattr(dns, attr):
                continue
            raw = getattr(dns, attr)
            if raw is None:
                continue
            addrs = [raw] if isinstance(raw, str) else list(raw)
            for ip in addrs:
                ip = str(ip).strip()
                if not ip:
                    continue
                self.domain_to_ips[name].add(ip)
                self.ip_to_domains[ip].add(name)

    
    @staticmethod
    def _stream_id(packet) -> str | None:
        if hasattr(packet, "tcp") and hasattr(packet.tcp, "stream"):
            return str(packet.tcp.stream)
        return None

    @staticmethod
    def _server_ip(packet) -> str | None:

        if not hasattr(packet, "ip"):
            return None
        src, dst = packet.ip.src, packet.ip.dst
        if not hasattr(packet, "tcp"):
            return dst
        sport, dport = str(packet.tcp.srcport), str(packet.tcp.dstport)
        if dport in HTTP_PORTS | HTTPS_PORTS:
            return dst
        if sport in HTTP_PORTS | HTTPS_PORTS:
            return src
        return dst

    def _bind_host(self, packet, hostname: str | None) -> str | None:

        hostname = self._norm_host(hostname)
        sid = self._stream_id(packet)
        if hostname and sid is not None:
            self.stream_hostname[sid] = hostname
        if hostname:
            return hostname
        if sid is not None:
            return self.stream_hostname.get(sid)
        return None

    def _record_destination(self, hostname: str | None, server_ip: str | None) -> None:
        if not hostname or not server_ip:
            return
        self.get_features(hostname)
        self.observed_destinations.add((hostname, server_ip))

    def _process_http(self, packet) -> None:
   
        http = packet.http
        host_hdr = getattr(http, "host", None) if hasattr(http, "host") else None
        hostname = self._bind_host(packet, host_hdr)
        server_ip = self._server_ip(packet)
        feats = self.get_features(hostname)
        if feats is None:
            return

        feats["http"] = True

        code = None
        if hasattr(http, "response_code") and http.response_code:
            code = str(http.response_code)
        elif hasattr(http, "status_code") and http.status_code:
            code = str(http.status_code)
        if code in REDIRECT_CODES:
            feats["Redirects"] += 1

        self._record_destination(hostname, server_ip)

    
    def _process_tls(self, packet) -> None:
      
        tls = packet.tls
        sni = None
        if hasattr(tls, "handshake_extensions_server_name"):
            sni = str(tls.handshake_extensions_server_name)

        hostname = self._bind_host(packet, sni)
        server_ip = self._server_ip(packet)
        feats = self.get_features(hostname)

        if hasattr(tls, "alert_level") and feats is not None:
            try:
                level = int(str(tls.alert_level))
            except ValueError:
                level = None
            if level == 2:
                # bad certificate, unknown CA, handshake_failure, etc.
                feats["tls_failures"] += 1

        self._record_destination(hostname, server_ip)

    
    def _check_dns_mismatches(self) -> None:
        
        for hostname, server_ip in self.observed_destinations:
            feats = self.get_features(hostname)
            if feats is None:
                continue

            known_ips = self.domain_to_ips.get(hostname, set())
            known_domains = self.ip_to_domains.get(server_ip, set())
            associated = (server_ip in known_ips) or (hostname in known_domains)

            if not associated:
                feats["Hostname_mismatch"] = True

   
    def extract(self) -> dict:
        capture = pyshark.FileCapture(self.file, keep_packets=False)
        try:
            for packet in capture:
                if hasattr(packet, "dns"):
                    self._process_dns(packet)
                if hasattr(packet, "http"):
                    self._process_http(packet)
                if hasattr(packet, "tls"):
                    self._process_tls(packet)
        finally:
            capture.close()

        self._check_dns_mismatches()
        risks = classify(self.domain_features)

        for domain, risk in sorted(risks.items()):
            f = self.domain_features[domain]
            print(
                f"{domain}: risk={risk:.2f} | "
                f"http={f['http']} redirects={f['Redirects']} "
                f"tls_failures={f['tls_failures']} "
                f"hostname_mismatch={f['Hostname_mismatch']}"
            )

        if self.domain_to_ips:
            print("\nDNS domain → IPs:")
            for d, ips in sorted(self.domain_to_ips.items()):
                print(f"  {d}: {sorted(ips)}")
        if self.ip_to_domains:
            print("\nDNS IP → domains:")
            for ip, doms in sorted(self.ip_to_domains.items()):
                print(f"  {ip}: {sorted(doms)}")
        if choice:
            out_path = Path(output)
            out_path.write_text(json.dumps(self.domain_features, indent=2), encoding="utf-8")
            print(f"\nWrote {out_path.resolve()}")
        return risks


if __name__ == "__main__":
    import sys
    filepath = Path(input("enter file path: ").strip().strip('"'))
    choice= (sys.argv[1] if len(sys.argv)>1 else 0)
    output=Path(sys.argv[2] if len(sys.argv)>2 else "pcap_features.json")
    if not filepath.is_file():
        raise SystemExit(f"file not found: {filepath}")
    FCap(filepath).extract()
