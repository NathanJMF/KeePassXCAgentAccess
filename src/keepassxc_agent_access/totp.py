"""RFC 6238 TOTP generation and protected custom-attribute lookup for KeePass entries."""

import base64
import hashlib
import hmac
import re
import struct
import time
import urllib.parse


_ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}
_ATTR_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_RESERVED_ATTRS = frozenset(("otp", "TOTP Seed", "TOTP Settings"))
_DIGITS_RE = re.compile(r"[0-9]+")
_BASE32_RE = re.compile(r"[A-Z2-7]+=*")


def _decode_base32(secret: str) -> bytes:
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    if not cleaned or not _BASE32_RE.fullmatch(cleaned):
        raise ValueError("Invalid Base32 TOTP secret.")
    padded = cleaned + ("=" * ((-len(cleaned)) % 8))
    try:
        key = base64.b32decode(padded, casefold=False)
    except ValueError:
        raise ValueError("Invalid Base32 TOTP secret.") from None
    if not key:
        raise ValueError("Empty TOTP secret.")
    return key


def _parse_int_param(value: str, low: int, high: int, label: str) -> int:
    text = value.strip()
    if not _DIGITS_RE.fullmatch(text):
        raise ValueError(f"Invalid TOTP {label}.")
    parsed = int(text)
    if not low <= parsed <= high:
        raise ValueError(f"Invalid TOTP {label}.")
    return parsed


def _generate_totp(secret: str, *, now: float | None, digits: int, period: int, algorithm: str) -> str:
    if now is None:
        now = time.time()
    if (isinstance(now, bool) or not isinstance(now, (int, float))
            or now != now or now in (float("inf"), float("-inf")) or now < 0):
        raise ValueError("Invalid TOTP timestamp.")
    digestmod = _ALGORITHMS.get(algorithm)
    if digestmod is None:
        raise ValueError("Unsupported TOTP algorithm.")
    key = _decode_base32(secret)
    counter = int(now) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, digestmod).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % (10 ** digits):0{digits}d}"


def otp_uri_secret(otp_value: str) -> str | None:
    """Return the raw secret query parameter when otp_value is an otpauth://totp URI."""
    if not isinstance(otp_value, str):
        return None
    raw = otp_value.strip()
    if not raw.lower().startswith("otpauth://"):
        return None
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme.lower() != "otpauth" or parts.netloc.lower() != "totp":
        return None
    secrets = urllib.parse.parse_qs(parts.query, keep_blank_values=True).get("secret")
    if not secrets or len(secrets) != 1 or not secrets[0].strip():
        return None
    return secrets[0].strip()


def compute_totp(otp_value: str, now: float | None = None) -> str:
    """Compute an RFC 6238 TOTP code from an otpauth://totp URI or raw Base32 secret."""
    if not isinstance(otp_value, str) or not otp_value.strip():
        raise ValueError("Empty TOTP secret.")
    raw = otp_value.strip()
    if raw.lower().startswith("otpauth://") or "://" in raw:
        parts = urllib.parse.urlsplit(raw)
        if parts.scheme.lower() != "otpauth" or parts.netloc.lower() != "totp":
            raise ValueError("Unsupported OTP URI; only otpauth://totp is supported.")
        params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        secret_values = params.get("secret")
        if not secret_values or len(secret_values) != 1 or not secret_values[0].strip():
            raise ValueError("Missing secret in TOTP URI.")
        digits = 6
        if "digits" in params:
            if len(params["digits"]) != 1:
                raise ValueError("Invalid TOTP digits.")
            digits = _parse_int_param(params["digits"][0], 6, 10, "digits")
        period = 30
        if "period" in params:
            if len(params["period"]) != 1:
                raise ValueError("Invalid TOTP period.")
            period = _parse_int_param(params["period"][0], 1, 300, "period")
        algorithm = "SHA1"
        if "algorithm" in params:
            if len(params["algorithm"]) != 1:
                raise ValueError("Invalid TOTP algorithm.")
            algorithm = params["algorithm"][0].strip().upper()
            if algorithm not in _ALGORITHMS:
                raise ValueError("Unsupported TOTP algorithm.")
        return _generate_totp(secret_values[0], now=now, digits=digits, period=period, algorithm=algorithm)
    return _generate_totp(raw, now=now, digits=6, period=30, algorithm="SHA1")


def entry_totp(entry, now: float | None = None) -> tuple[str, str]:
    """Compute (code, raw_secret_or_uri) for a KeePass entry or raise ValueError."""
    props = getattr(entry, "custom_properties", None)
    props_dict = props if isinstance(props, dict) else {}

    otp_attr = getattr(entry, "otp", None)
    if isinstance(otp_attr, str) and otp_attr.strip():
        return compute_totp(otp_attr, now=now), otp_attr

    otp_prop = props_dict.get("otp")
    if isinstance(otp_prop, str) and otp_prop.strip():
        return compute_totp(otp_prop, now=now), otp_prop

    seed = props_dict.get("TOTP Seed")
    if isinstance(seed, str) and seed.strip():
        settings = props_dict.get("TOTP Settings")
        if settings is not None and not isinstance(settings, str):
            raise ValueError("Invalid TOTP Settings.")
        if isinstance(settings, str) and settings.strip() and not seed.strip().lower().startswith("otpauth://"):
            parts = settings.strip().split(";")
            if len(parts) != 2:
                raise ValueError("Invalid TOTP Settings.")
            period = _parse_int_param(parts[0], 1, 300, "period")
            digits = _parse_int_param(parts[1], 6, 10, "digits")
            return _generate_totp(seed, now=now, digits=digits, period=period, algorithm="SHA1"), seed
        return compute_totp(seed, now=now), seed

    raise ValueError("Entry has no TOTP secret.")


def entry_custom_attr(entry, name: str) -> str:
    """Read a non-empty named custom string attribute from a KeePass entry."""
    if not isinstance(name, str) or not _ATTR_NAME.fullmatch(name) or name in _RESERVED_ATTRS:
        raise ValueError("Invalid custom attribute name.")
    props = getattr(entry, "custom_properties", None)
    value = props.get(name) if isinstance(props, dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError(f"Missing custom attribute: {name}")
    return value
