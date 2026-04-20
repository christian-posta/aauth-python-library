"""Shim: re-exports :mod:`aauth_signing` as :mod:`aauth.signing` for backwards compatibility."""

import aauth_signing as _signing
from aauth_signing import *  # noqa: F403

__all__ = _signing.__all__
