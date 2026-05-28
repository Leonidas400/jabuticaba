"""
vendor_base.py — Common base for all firewall vendors.
Generic check runner + shared helpers.
"""

import importlib
from database import get_endpoints_by_vendor, rule_defs_get_disabled_tags
from api_runner import run_db_checks


# ── UNIVERSAL HELPERS ──────────────────────────────────────

def _t(v):
    """Truthy check — universal."""
    if v is None: return False
    if isinstance(v, bool): return v
    if isinstance(v, (int, float)): return v != 0
    return str(v).lower() in ("true", "1", "yes", "enable", "enabled", "on", "active")


def _bv(v):
    """Boolean to on/off string."""
    if _t(v): return "on"
    if v is None: return "—"
    return "off"


def _d(obj, *keys, default=None):
    """Deep access dict with fallback."""
    for k in keys:
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


def _dl(obj):
    """Unwrap list-or-dict response (FortiGate pattern)."""
    if obj is None: return None
    if isinstance(obj, list): return obj
    if isinstance(obj, dict):
        if "results" in obj: return obj["results"]
        return obj
    return obj


def _safe_int(v, fallback=-1):
    try:
        return int(v)
    except (ValueError, TypeError):
        return fallback


# ── GENERIC CHECK RUNNER ───────────────────────────────────

def run_api_checks_generic(vendor_slug, client, handler_module_name):
    """
    Generic API check runner — works for ANY vendor.
    Uses DB-backed endpoints (SonicWall mature pattern).
    
    Args:
        vendor_slug: e.g. "sonicwall", "fortigate", "pfsense"
        client: API client instance with .get(path) method
        handler_module_name: e.g. "sonicwall_api", "fortigate_api"
    
    Returns:
        (checks_list, data_dict)
    """
    handler_module = importlib.import_module(handler_module_name)
    _HANDLERS = getattr(handler_module, '_HANDLERS', {})

    endpoints_db = get_endpoints_by_vendor(vendor_slug)
    data = {}

    for ep in endpoints_db:
        section = ep['section_name'].strip()
        path = ep['endpoint_path'].strip()
        response = client.get(path)
        data[section] = response if response else {}

    try:
        data["_disabled_rule_tags"] = rule_defs_get_disabled_tags(vendor_slug)
    except Exception:
        data["_disabled_rule_tags"] = set()

    checks = run_db_checks(vendor_slug, data, _HANDLERS)
    return checks, data