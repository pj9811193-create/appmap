"""graph.py - build and render the AppMap relationship graph.

The graph models the chain the tool discovers:

    Domain
      -> DNS records
      -> Web service
      -> TLS certificate
      -> Discovered application metadata

It is produced as a plain nested dictionary (easy to export to JSON) and can be
rendered either as an ASCII tree for the terminal or as nodes/edges for a
graphical dashboard.
"""

from __future__ import annotations

from typing import Dict, List

from dns_analyzer import DNSResult, RECORD_ORDER
from http_analyzer import HTTPResult
from tls_analyzer import TLSResult


class GraphBuilder:
    """Turns analyzer results into a nested graph plus a node/edge view."""

    def __init__(
        self,
        hostname: str,
        dns: DNSResult,
        http: HTTPResult | None = None,
        tls: TLSResult | None = None,
    ):
        self.hostname = hostname
        self.dns = dns
        self.http = http
        self.tls = tls

    # ------------------------------------------------------------------ #
    # Nested dictionary form
    # ------------------------------------------------------------------ #
    def build(self) -> dict:
        root = {
            "name": self.hostname,
            "type": "domain",
            "children": [],
        }

        dns_node = {"name": "DNS", "type": "dns", "children": []}
        for rtype in RECORD_ORDER:
            values = self.dns.records.get(rtype, [])
            for value in values:
                dns_node["children"].append(
                    {"name": f"{rtype} {value}", "type": "dns_record", "record_type": rtype}
                )
        if not dns_node["children"]:
            dns_node["children"].append({"name": "(no records)", "type": "note"})
        root["children"].append(dns_node)

        if self.http is not None:
            scheme = (self.http.scheme or "http").upper()
            web_node = {
                "name": f"{scheme} service",
                "type": "web_service",
                "children": [],
            }
            if self.http.ok:
                web_node["children"].append(
                    {
                        "name": f"Status {self.http.status_code} {self.http.reason or ''}".strip(),
                        "type": "http_status",
                    }
                )
                if self.http.content_type:
                    web_node["children"].append(
                        {"name": f"Content-Type: {self.http.content_type}", "type": "http_meta"}
                    )
                if self.http.server:
                    web_node["children"].append(
                        {"name": f"Server: {self.http.server}", "type": "http_meta"}
                    )
                for header, value in self.http.hints.items():
                    if header == "Server":
                        continue
                    web_node["children"].append(
                        {"name": f"{header}: {value}", "type": "http_meta"}
                    )
            else:
                web_node["children"].append(
                    {"name": f"unavailable: {self.http.error}", "type": "note"}
                )
            root["children"].append(web_node)

        if self.tls is not None and (self.tls.connected or self.tls.error):
            tls_node = {"name": "TLS", "type": "tls", "children": []}
            if self.tls.tls_version:
                tls_node["children"].append(
                    {"name": self.tls.tls_version, "type": "tls_meta"}
                )
            if self.tls.subject:
                tls_node["children"].append(
                    {
                        "name": f"subject CN={self.tls.subject.get('commonName', '?')}",
                        "type": "tls_meta",
                    }
                )
            if self.tls.issuer:
                tls_node["children"].append(
                    {
                        "name": f"issuer {self.tls.issuer.get('organizationName') or self.tls.issuer.get('commonName', '?')}",
                        "type": "tls_meta",
                    }
                )
            if self.tls.days_until_expiry is not None:
                tls_node["children"].append(
                    {
                        "name": f"expires in {self.tls.days_until_expiry} days",
                        "type": "tls_meta",
                    }
                )
            if self.tls.sans:
                tls_node["children"].append(
                    {
                        "name": f"SANs ({len(self.tls.sans)}): {', '.join(self.tls.sans[:5])}"
                        + (" ..." if len(self.tls.sans) > 5 else ""),
                        "type": "tls_meta",
                    }
                )
            if self.tls.error:
                tls_node["children"].append(
                    {"name": self.tls.error, "type": "note"}
                )
            root["children"].append(tls_node)

        return root

    # ------------------------------------------------------------------ #
    # ASCII tree for the terminal
    # ------------------------------------------------------------------ #
    @staticmethod
    def render_ascii(tree: dict) -> str:
        lines: List[str] = []

        def walk(node: dict, prefix: str, is_last: bool, is_root: bool = False) -> None:
            if is_root:
                lines.append(node["name"])
            else:
                connector = "└── " if is_last else "├── "
                lines.append(f"{prefix}{connector}{node['name']}")
            children = node.get("children", [])
            if is_root:
                child_prefix = ""
            else:
                child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child in enumerate(children):
                walk(child, child_prefix, i == len(children) - 1)

        walk(tree, "", True, is_root=True)
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Node/edge form for the dashboard
    # ------------------------------------------------------------------ #
    def build_nodes_edges(self) -> dict:
        tree = self.build()
        nodes: List[dict] = []
        edges: List[dict] = []
        counter = {"i": 0}

        def walk(node: dict, parent_id: str | None) -> None:
            node_id = f"n{counter['i']}"
            counter["i"] += 1
            nodes.append({"id": node_id, "label": node["name"], "type": node.get("type", "node")})
            if parent_id is not None:
                edges.append({"from": parent_id, "to": node_id})
            for child in node.get("children", []):
                walk(child, node_id)

        walk(tree, None)
        return {"nodes": nodes, "edges": edges}
