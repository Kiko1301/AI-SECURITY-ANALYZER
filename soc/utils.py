"""
Shared low-level helpers: timestamps + a safe HTTP wrapper that never
raises (except KeyboardInterrupt) so callers can treat every network
call as "maybe None" instead of wrapping everything in try/except.
"""
from datetime import datetime
import requests

# Stores the real exception text from the last failed safe_request()
# call, so callers can log *why* something failed without re-raising.
_last_request_error: str = ""


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_request(method: str, url: str, **kwargs):
    """
    Returns None on any failure. Always re-raises KeyboardInterrupt.
    Stores the real exception in _last_request_error so callers can log it.
    Pass debug=True to print the error immediately.
    """
    global _last_request_error
    debug = kwargs.pop("debug", False)
    try:
        return requests.request(method, url, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        _last_request_error = f"{type(exc).__name__}: {exc}"
        if debug:
            # Local import to avoid a circular dependency with ui.py
            from soc.ui import status_warn
            status_warn(f"HTTP {method} {url} failed  →  {_last_request_error}")
        return None


def get_last_request_error() -> str:
    return _last_request_error
