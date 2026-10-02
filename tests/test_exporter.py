"""Tests for JSON/CSV export and TLS helpers."""
import csv
import json
import os

from exporter import Exporter


def _sample_result():
    return {
        "target": "example.com",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "dns": {"records": {"A": ["93.184.216.34"], "MX": ["10 mail.example.com"]}},
        "http": {
            "status_code": 200,
            "final_url": "https://example.com",
            "content_type": "text/html",
            "server": "nginx",
        },
        "tls": {
            "tls_version": "TLS 1.3",
            "issuer": {"organizationName": "Example CA"},
            "not_after": "Jan  1 00:00:00 2027 GMT",
            "days_until_expiry": 365,
        },
    }


def test_export_json_roundtrip(tmp_path):
    exporter = Exporter(output_dir=str(tmp_path))
    path = exporter.export_json(_sample_result(), str(tmp_path / "out.json"))
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["target"] == "example.com"
    assert data["dns"]["records"]["A"] == ["93.184.216.34"]


def test_export_json_autoname(tmp_path):
    exporter = Exporter(output_dir=str(tmp_path))
    path = exporter.export_json(_sample_result())
    assert path.endswith(".json")
    assert "example.com" in os.path.basename(path)


def test_export_csv_summary(tmp_path):
    exporter = Exporter(output_dir=str(tmp_path))
    path = exporter.export_csv_summary(_sample_result(), str(tmp_path / "s.csv"))
    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["target"] == "example.com"
    assert rows[0]["a_records"] == "93.184.216.34"
    assert rows[0]["cert_issuer"] == "Example CA"