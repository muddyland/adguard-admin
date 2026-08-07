"""Unit coverage for the validation layer everything else leans on."""
from __future__ import annotations

import pytest

from app.validators import (
    ValidationError,
    format_host_port,
    is_valid_host,
    validate_display_name,
    validate_host,
    validate_port,
    validate_server_url,
)


@pytest.mark.parametrize("host", [
    "example.com", "agh.home.lan", "host-1", "a.b.c.d.e.f",
    "10.0.0.1", "255.255.255.255", "::1", "fd00::1", "example.com.",
])
def test_valid_hosts(host):
    assert is_valid_host(host)


@pytest.mark.parametrize("host", [
    "", "-leading.test", "trailing-.test", "has space", "has;semi", "has/slash",
    "http://example.com", "a" * 64 + ".test", "a" * 254, "under_score.test",
    "with\nnewline", "1.2.3.4:5678", "example.com/../x", "a@b.test",
])
def test_invalid_hosts(host):
    assert not is_valid_host(host)


def test_all_numeric_labels_are_valid_hostnames():
    """Not an IPv4 address, but a syntactically legal DNS name — accepted on
    purpose so we don't reject real (if unusual) internal names."""
    assert is_valid_host("256.256.256.256")


def test_validate_host_strips_and_returns():
    assert validate_host("  example.com  ") == "example.com"


def test_validate_host_rejects():
    with pytest.raises(ValidationError):
        validate_host("not a host")


@pytest.mark.parametrize("name", ["edge-1", "Site A (backup)", "x" * 100])
def test_valid_display_names(name):
    assert validate_display_name(name) == name


@pytest.mark.parametrize("name", ["", "   ", "x" * 101, "with\nnewline", "with\ttab", "nul\x00"])
def test_invalid_display_names(name):
    with pytest.raises(ValidationError):
        validate_display_name(name)


def test_display_name_allows_quotes_but_they_get_quoted_downstream():
    """Quotes are legitimate in a name; safety comes from shlex.quote at render."""
    assert validate_display_name("Bob's box") == "Bob's box"


@pytest.mark.parametrize("port", [1, 80, 3000, 65535])
def test_valid_ports(port):
    assert validate_port(port) == port


@pytest.mark.parametrize("port", [0, -1, 65536, True, "80", 1.5])
def test_invalid_ports(port):
    with pytest.raises(ValidationError):
        validate_port(port)


@pytest.mark.parametrize("url", [
    "http://10.0.0.2:3000", "https://agh.example.com", "http://host-1:8080",
    "https://[fd00::1]:443",
])
def test_valid_server_urls(url):
    assert validate_server_url(url) == url.rstrip("/")


@pytest.mark.parametrize("url", [
    "ftp://example.com", "file:///etc/passwd", "example.com", "",
    "http://", "http://exa mple.com", "http://example.com:99999",
    "javascript:alert(1)", "http://ex\nample.com",
])
def test_invalid_server_urls(url):
    with pytest.raises(ValidationError):
        validate_server_url(url)


def test_server_url_trailing_slash_normalised():
    assert validate_server_url("http://10.0.0.2:3000/") == "http://10.0.0.2:3000"


def test_format_host_port_brackets_ipv6():
    assert format_host_port("fd00::1", 443) == "[fd00::1]:443"
    assert format_host_port("10.0.0.1", 3000) == "10.0.0.1:3000"
    assert format_host_port("example.com", 80) == "example.com:80"
