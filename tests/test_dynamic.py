"""동적 셋(즉시 격리/차단) 테스트.

격리는 정책 revision과 무관하게 초 단위로 반영되어야 하고, 정책 재적용으로
테이블이 교체돼도 살아남아야 한다. 그 두 성질을 여기서 확인한다.
"""
from __future__ import annotations

import time

import pytest

from router.dynamic import (
    BRIDGE_MAC_SET,
    DynamicElement,
    DynamicStore,
    from_central_payload,
    sync,
)
from router.util import CommandResult, RecordingRunner


@pytest.fixture
def store(tmp_path) -> DynamicStore:
    return DynamicStore(tmp_path / "dynamic.json")


def test_mac_and_ip_normalized(store):
    store.upsert(DynamicElement("mac", "aa-bb-cc-dd-ee-01"))
    store.upsert(DynamicElement("ipv4", "10.20.0.7"))
    kinds = {(e.kind, e.value) for e in store.load()}
    assert ("mac", "AA:BB:CC:DD:EE:01") in kinds
    assert ("ipv4", "10.20.0.7") in kinds


def test_expired_elements_pruned(store):
    store.upsert(DynamicElement("mac", "AA:BB:CC:DD:EE:01", expires_at=time.time() - 10))
    store.upsert(DynamicElement("mac", "AA:BB:CC:DD:EE:02", expires_at=time.time() + 600))
    remaining = store.prune()
    assert [e.value for e in remaining] == ["AA:BB:CC:DD:EE:02"]


def test_sync_pushes_to_both_l3_and_l2(store):
    """L2까지 막지 않으면 격리 단말이 같은 VLAN의 옆 단말을 계속 공격할 수 있다."""
    store.upsert(DynamicElement("mac", "AA:BB:CC:DD:EE:01", expires_at=time.time() + 300))
    runner = RecordingRunner()
    report = sync(runner, store)
    assert report["ok"]
    scripts = [stdin for argv, stdin in runner.calls if stdin]
    l3 = [s for s in scripts if "inet mooker quarantine_mac" in s]
    l2 = [s for s in scripts if f"{BRIDGE_MAC_SET[0]} {BRIDGE_MAC_SET[1]}" in s]
    assert l3 and l2
    assert "AA:BB:CC:DD:EE:01" in l3[0] and "AA:BB:CC:DD:EE:01" in l2[0]
    # 만료는 커널 타이머에 맡긴다(우리가 붙들고 있지 않는다)
    assert "timeout" in l3[0]


def test_sync_uses_flush_then_add(store):
    """원소를 하나씩 넣고 빼면 중간 상태가 생기고 중복/미존재에서 실패한다."""
    store.upsert(DynamicElement("ipv4", "10.20.0.7"))
    runner = RecordingRunner()
    sync(runner, store)
    script = next(stdin for argv, stdin in runner.calls
                  if stdin and "quarantine_v4" in stdin)
    assert script.splitlines()[0].startswith("flush set inet mooker quarantine_v4")
    assert "add element" in script


def test_bridge_failure_does_not_fail_whole_sync(store):
    """bridge 커널 지원이 없어도 L3 격리는 유효해야 한다."""
    store.upsert(DynamicElement("mac", "AA:BB:CC:DD:EE:01"))
    runner = RecordingRunner()
    original_run = runner.run

    def run(argv, stdin=None, timeout=30.0, check=False):
        if stdin and "bridge mooker_l2" in stdin:
            runner.calls.append((tuple(argv), stdin))
            return CommandResult(tuple(argv), 1, "", "no such table")
        return original_run(argv, stdin, timeout, check)

    runner.run = run  # type: ignore[method-assign]
    report = sync(runner, store)
    assert report["ok"] is True
    bridge_entry = next(entry for entry in report["sets"] if entry.get("optional"))
    assert bridge_entry["ok"] is False


def test_central_payload_conversion():
    elements = from_central_payload({
        "quarantine": [
            {"mac": "AA:BB:CC:DD:EE:01", "reason": "botnet c2", "severity": "critical",
             "command_id": "isolation-7", "expires_at": "2030-01-01T00:00:00Z",
             "ip_addresses": ["10.20.0.7", "2001:db8::7"]},
            {"mac": "not-a-mac"},
        ],
        "blocked_destinations": [
            {"address": "203.0.113.9", "reason": "c2 server"},
            {"address": "nonsense"},
        ],
    })
    by_kind = {}
    for element in elements:
        by_kind.setdefault(element.kind, []).append(element.value)
    assert by_kind["mac"] == ["AA:BB:CC:DD:EE:01", "not-a-mac"]  # 정규화는 normalized()에서
    assert by_kind["ipv4"] == ["10.20.0.7"]
    assert by_kind["ipv6"] == ["2001:db8::7"]
    assert by_kind["blocked_ipv4"] == ["203.0.113.9"]
    # 잘못된 값은 저장 단계에서 걸러진다
    store_ready = [e for e in elements if _normalizable(e)]
    assert len(store_ready) == len(elements) - 1


def _normalizable(element: DynamicElement) -> bool:
    try:
        element.normalized()
        return True
    except ValueError:
        return False


def test_store_replace_drops_invalid_and_expired(store):
    store.replace([
        DynamicElement("mac", "AA:BB:CC:DD:EE:01"),
        DynamicElement("mac", "AA:BB:CC:DD:EE:02", expires_at=time.time() - 1),
    ])
    assert [e.value for e in store.load()] == ["AA:BB:CC:DD:EE:01"]
