"""Geolocation helpers for impossible-travel detection.

This module uses only the Python standard library (`urllib`, `json`, `math`,
`ipaddress`). The login flow calls it after successful password verification;
any provider problem is handled as a fail-open condition so legitimate users
are never blocked by a transient outage.
"""

import ipaddress
import json
import logging
import math
import os
import urllib.request

logger = logging.getLogger(__name__)


def normalize_ip(raw_ip: str) -> str:
    """Return a trimmed IP string, or an empty string when absent."""
    if not raw_ip:
        return ""
    return str(raw_ip).strip()


def is_local_or_private(raw_ip: str) -> bool:
    """Return True for loopback/private IPv4/IPv6 addresses and invalid input."""
    ip_text = normalize_ip(raw_ip)
    if not ip_text:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    return ip_obj.is_loopback or ip_obj.is_private


def lookup_coordinates(raw_ip: str) -> dict | None:
    """Look up coordinates for a non-private IP using a free geo API.

    Returns a ``{"lat": ..., "lon": ...}`` dict when available, otherwise
    ``None``. Any exception is treated as a fail-open condition: the caller
    should allow login and persist the last-login metadata without coordinates.
    """
    ip_text = normalize_ip(raw_ip)
    api_url = os.environ.get("GEO_API_URL", "")
    if not api_url or is_local_or_private(ip_text):
        return None

    try:
        request_url = api_url.format(ip=ip_text)
        req = urllib.request.Request(request_url, method="GET")
        with urllib.request.urlopen(req, timeout=float(os.environ.get("GEO_HTTP_TIMEOUT", "5"))) as response:
            data = json.loads(response.read().decode("utf-8"))
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return None
        return {"lat": float(lat), "lon": float(lon)}
    except Exception:
        logger.warning(
            "Geolocation lookup failed for %s; allowing login and updating metadata without coordinates.",
            ip_text,
        )
        return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in kilometers between two points."""
    earth_radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return earth_radius_km * c


def should_flag_impossible_travel(
    prev_lat: float | None,
    prev_lon: float | None,
    prev_time: float | None,
    curr_lat: float | None,
    curr_lon: float | None,
    curr_time: float | None,
) -> bool:
    """Return True when speed between two locations exceeds 1000 km/h."""
    if None in (prev_lat, prev_lon, prev_time, curr_lat, curr_lon, curr_time):
        return False
    if curr_time <= prev_time:
        return False
    distance_km = haversine_km(prev_lat, prev_lon, curr_lat, curr_lon)
    elapsed_hours = (curr_time - prev_time) / 3600.0
    if elapsed_hours <= 0:
        return False
    speed_kmh = distance_km / elapsed_hours
    return speed_kmh > 1000.0
