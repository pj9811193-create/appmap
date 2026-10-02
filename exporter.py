"""exporter.py - persist AppMap results to JSON (and a tiny CSV summary)."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from typing import Optional


class Exporter:
    """Writes a scan result to disk. All output is plain, human-readable text."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def _ensure_dir(self) -> None:
        if self.output_dir and not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def export_json(self, result: dict, path: Optional[str] = None) -> str:
        self._ensure_dir()
        if path is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            safe_host = result.get("target", "target").replace("/", "_").replace(":", "_")
            path = os.path.join(self.output_dir, f"appmap_{safe_host}_{stamp}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        return path

    def export_csv_summary(self, result: dict, path: Optional[str] = None) -> str:
        """A one-row CSV summary, handy for tracking many hosts over time."""
        self._ensure_dir()
        if path is None:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = os.path.join(self.output_dir, f"appmap_summary_{stamp}.csv")

        dns = result.get("dns", {}).get("records", {})
        http = result.get("http", {}) or {}
        tls = result.get("tls", {}) or {}
        row = {
            "target": result.get("target", ""),
            "scanned_at": result.get("scanned_at", ""),
            "a_records": ";".join(dns.get("A", [])),
            "status_code": http.get("status_code", ""),
            "final_url": http.get("final_url", ""),
            "content_type": http.get("content_type", ""),
            "server": http.get("server", ""),
            "tls_version": tls.get("tls_version", ""),
            "cert_issuer": (tls.get("issuer") or {}).get("organizationName", ""),
            "cert_expires": tls.get("not_after", ""),
            "days_until_expiry": tls.get("days_until_expiry", ""),
        }
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
            writer.writeheader()
            writer.writerow(row)
        return path
