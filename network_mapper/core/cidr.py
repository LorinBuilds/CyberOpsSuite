"""CIDR helpers for CyberOpsSuite Network Mapper.

Converts a CIDR string into a bounded list of usable IPv4 addresses. A hard
ceiling (``MAX_HOSTS``) prevents accidental scanning of very large ranges.
"""

from __future__ import annotations

import ipaddress

#: Upper bound on usable hosts in a single scan target. Keeps the GUI
#: responsive and avoids accidentally probing a whole /16.
MAX_HOSTS = 1024


class CidrError(ValueError):
    """Raised when a scan target cannot be parsed or exceeds ``MAX_HOSTS``."""


def cidr_to_range(cidr: str, max_hosts: int = MAX_HOSTS) -> list[str]:
    """Return the usable host addresses of an IPv4 CIDR block.

    Parameters
    ----------
    cidr:
        An IPv4 network in CIDR notation, e.g. ``"192.168.1.0/24"``.
        ``strict=False`` semantics apply, so host bits are tolerated.
    max_hosts:
        Maximum number of usable hosts to allow. Raises :class:`CidrError`
        if the network is larger than this.

    Raises
    ------
    CidrError
        If *cidr* is not valid IPv4, or if the network exceeds *max_hosts*.
    """
    try:
        network = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except (ValueError, TypeError) as exc:
        raise CidrError(f"Invalid CIDR: {cidr!r}") from exc

    if network.version != 4:
        raise CidrError(f"Only IPv4 is supported, got: {cidr!r}")

    usable = max(0, network.num_addresses - 2)  # subtract network and broadcast
    if usable > max_hosts:
        raise CidrError(
            f"Range too large: {usable} usable hosts, limit is {max_hosts}."
        )

    return [str(ip) for ip in network.hosts()]