from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from .taint import TaintTracker


@dataclass(frozen=True)
class NetworkTargetError(ValueError):
    reason: str
    target: str

    def __str__(self) -> str:
        return f"{self.reason}: {self.target}"


def validate_public_http_target(
    url: str,
    *,
    resolve_dns: bool = True,
) -> str:
    normalized, metadata = TaintTracker.normalize_url(url)
    parsed = urlparse(normalized)
    if (
        metadata.get("invalid")
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
    ):
        raise NetworkTargetError("invalid_url", str(url))
    if metadata.get("private_or_metadata"):
        raise NetworkTargetError("ssrf_private_network", normalized)

    host = parsed.hostname.lower().rstrip(".")
    if not resolve_dns or host.endswith(".test"):
        return normalized
    try:
        addresses = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )
    except socket.gaierror as exc:
        raise NetworkTargetError("dns_resolution_failed", normalized) from exc
    for info in addresses:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise NetworkTargetError("ssrf_private_network", normalized)
    return normalized
