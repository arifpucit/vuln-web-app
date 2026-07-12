"""Have I Been Pwned (HIBP) password breach detection.

Implements k-anonymity protection by only sending the first 5 hex characters
of a SHA-1 hash to the HIBP API, preventing exposure of full password hashes.

See: https://haveibeenpwned.com/API/v3#RangeSearch
"""

import hashlib
import urllib.request
import urllib.error
from typing import Optional

from app.core import config


HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
HIBP_TIMEOUT = 10.0  # seconds


def is_password_compromised(password: str) -> bool:
    """Check if password appears in breach database using k-anonymity.

    Args:
        password: The plain-text password to check

    Returns:
        True if the password has been found in a data breach, False otherwise
    """
    if not password:
        return False

    # SHA-1 the password (hexadecimal, uppercase) as required by HIBP API
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Split into prefix (first 5 chars) and suffix (rest) for k-anonymity
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Query HIBP API for hash range with this prefix
    try:
        request = urllib.request.Request(f"{HIBP_API_URL}{prefix}")
        with urllib.request.urlopen(request, timeout=HIBP_TIMEOUT) as response:
            # Check if our suffix is in the returned list of suffixes
            # Each line is in format: SUFFIX:COUNT
            return any(line.startswith(f"{suffix}:") for line in response.read().decode('utf-8').splitlines())
    except Exception:
        # FAIL OPEN: a broken/unreachable provider must not deny all logins.
        # (Do not log the password or any sensitive information.)
        return False
