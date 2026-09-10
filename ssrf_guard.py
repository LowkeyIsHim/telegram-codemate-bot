"""
ssrf_guard.py — blocks any tool that makes an outbound connection directly
to a user-supplied target from being pointed at internal/private network
addresses instead (localhost, RFC1918 ranges, link-local/cloud metadata
like 169.254.169.254, etc.) — a well-known bug class (SSRF) where a tool
meant to check external sites gets tricked into probing internal
infrastructure instead, including the bot's own host.

Only used by tools where OUR SERVER makes the outbound request itself
(/headers, /sslcheck, /audit, /techstack, /robots, /securitytxt,
/portscan). Tools like /whois, /dns, /wayback, /subdomains talk to a
registrar/resolver/archive about the target rather than connecting to it
directly, so they aren't SSRF vectors and don't need this check.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def _extract_host(target: str) -> str:
    """Pull just the hostname out of a bare domain, an IP, or a full URL."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def is_blocked_target(target: str):
    """Returns a warning string if `target` resolves to a private/internal
    address, or None if it looks like a legitimate external target.
    Resolution failures return None too — an unreachable/invalid host
    should fail with its own clear error from the actual request, not
    a confusing SSRF-guard message."""
    host = _extract_host(target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return (
            f"🚫 '{host}' resolves to {ip}, a private/internal address. "
            "This tool only works against public targets — pointing it at "
            "internal infrastructure (including this bot's own host) isn't allowed."
        )
    return None
