import socket

import pytest

from security_review.infrastructure.security.outbound_url_validation import (
    UnsafeOutboundUrlError,
    validate_public_http_url,
)


def _resolution(addresses: list[str]):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]


def test_rejects_loopback_address() -> None:
    with pytest.raises(UnsafeOutboundUrlError, match="private"):
        validate_public_http_url("http://127.0.0.1:8080/admin")


def test_rejects_private_dns_resolution(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _resolution(["10.0.0.5"]))

    with pytest.raises(UnsafeOutboundUrlError, match="private"):
        validate_public_http_url("https://internal.example")


def test_rejects_mixed_public_and_private_dns_resolution(monkeypatch) -> None:
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *_args, **_kwargs: _resolution(["8.8.8.8", "169.254.169.254"])
    )

    with pytest.raises(UnsafeOutboundUrlError, match="private"):
        validate_public_http_url("https://mixed.example")


def test_allows_public_dns_resolution(monkeypatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: _resolution(["8.8.8.8"]))

    assert validate_public_http_url("https://public.example/path") == "https://public.example/path"
