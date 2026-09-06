"""Fail-closed validation for user-controlled outbound HTTP destinations."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


class UnsafeOutboundUrlError(ValueError):
    """Raised when a URL could reach a non-public network destination."""


def validate_public_http_url(url: str) -> str:
    """Return ``url`` only when it resolves exclusively to public IP addresses.

    This prevents the service from becoming an SSRF primitive through webhooks,
    repository imports, or active URL scans. DNS failures are rejected rather
    than passed to the HTTP client, because a fail-open policy would make DNS
    rebinding and internal-only names reachable.
    """

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeOutboundUrlError("Outbound URL has an invalid port.") from exc

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise UnsafeOutboundUrlError("Outbound URL must use http:// or https:// and include a hostname.")
    if parsed.username or parsed.password:
        raise UnsafeOutboundUrlError("Outbound URL must not contain user credentials.")

    _validate_public_host(hostname, port)
    return url


def _validate_public_host(hostname: str, port: int) -> None:
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise UnsafeOutboundUrlError("Outbound URL hostname could not be resolved.") from exc

    if not addresses:
        raise UnsafeOutboundUrlError("Outbound URL hostname did not resolve to an address.")

    for address_text in addresses:
        address = ipaddress.ip_address(address_text)
        if not address.is_global:
            raise UnsafeOutboundUrlError(
                "Outbound URL resolves to a private, loopback, link-local, or reserved address."
            )
