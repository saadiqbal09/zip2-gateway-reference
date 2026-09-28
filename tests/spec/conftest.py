"""Shared fixtures."""
from __future__ import annotations
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
import pytest

@pytest.fixture
def frozen_now():
    return datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)

@pytest.fixture
def clock_synced(frozen_now):
    class _C:
        def __init__(self):
            self._t = frozen_now
            self._synced = True
        def now(self): return self._t
        def monotonic(self): return self._t.timestamp()
        def synced(self): return self._synced
        def advance(self, s):
            from datetime import timedelta
            self._t = self._t + timedelta(seconds=s)
        def set_synced(self, v): self._synced = v
    return _C()

@pytest.fixture
def attacker_ip(): return IPv4Address("203.0.113.25")

@pytest.fixture
def device_mac(): return "AA:BB:CC:DD:EE:01"

@pytest.fixture
def gateway_id(): return "test-gateway-01"
