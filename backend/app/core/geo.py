"""Geolocation helpers for impossible-travel detection.

Uses stdlib urllib/json/math only. The login flow calls this helper after
successful password verification; any provider issue is treated as a fail-open
condition so legitimate users are not blocked by a transient outage.
"""

import ipaddress
import json
import logging
import math
import urllib.parse
import urllib.request

from app.core import config

logger = logging.getLogger(__name__)


def normalize_ip(raw_ip: str) -> str:
    """Normalize/clean an IP string for downstream checks."""
    if not raw_ip:
        return ""
    return raw_ip.strip()


def is_local_or_private(raw_ip: str) -> bool:
    """Return True for localhost/private IPs that should bypass lookup."""
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

    Returns {"lat": float, "lon": float} when available, otherwise None.
    Any exception is treated as a fail-open condition.
    """
    if not config.is_geo_configured() or is_local_or_private(raw_ip):
        return None

    try:
        url = config.GEO_API_URL.format(ip=normalize_ip(raw_ip))
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=config.GEO_HTTP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        lat = data.get("lat")
        lon = data.get("lon")
        if lat is None or lon is None:
            return None
        return {"lat": float(lat), "lon": float(lon)}
    except Exception:
        logger.warning("Geolocation lookup failed for %s; allowing login and updating metadata without coordinates.", raw_ip)
        return None


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in kilometers between two points."""
    radius_km = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(delta_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius_km * c


def should_flag_impossible_travel(
    prev_lat: float | None,
    prev_lon: float | None,
    prev_time: float | None,
    curr_lat: float | None,
    curr_lon: float | None,
    curr_time: float | None,
) -> bool:
    """Return True when travel speed exceeds 1000 km/h between two known points."""
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