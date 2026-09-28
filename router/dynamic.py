"""동적 셋 관리: 즉시 격리와 위협 목적지 차단.

정책(desired state)과 달리 이것들은 '초 단위로 바뀌는 운영 판단'이다. 전체
룰셋을 다시 만들지 않고 named set의 원소만 넣고 뺀다. nftables set의 timeout
기능을 쓰므로 만료 관리를 우리가 붙들고 있지 않아도 커널이 스스로 정리한다.

두 곳에 동시에 반영한다.
- ``inet mooker``     : L3 차단 (인터넷/세그먼트 간)
- ``bridge mooker_l2``: L2 차단 (같은 세그먼트 안에서 옆 단말과의 통신)

L2까지 막지 않으면 격리된 단말이 같은 VLAN의 다른 PC를 계속 공격할 수 있다.
현장 격리의 목적을 생각하면 이쪽이 더 중요하다.

정책을 재적용하면 테이블이 교체되어 set이 비므로, 적용 직후 ``sync``가 다시
채운다. 그래서 이 저장소가 단일 진실 공급원이다.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .paths import STATE_DIR
from .util import LOG, CommandRunner, atomic_write, check_address, normalize_mac

DYNAMIC_FILE = f"{STATE_DIR}/dynamic.json"

SET_FOR_KIND = {
    "mac": ("inet", "mooker", "quarantine_mac"),
    "ipv4": ("inet", "mooker", "quarantine_v4"),
    "ipv6": ("inet", "mooker", "quarantine_v6"),
    "blocked_ipv4": ("inet", "mooker", "blocked_dst_v4"),
    "blocked_ipv6": ("inet", "mooker", "blocked_dst_v6"),
    "admitted_mac": ("inet", "mooker", "admitted_mac"),
}
BRIDGE_MAC_SET = ("bridge", "mooker_l2", "quarantine_mac")


@dataclass
class DynamicElement:
    kind: str
    value: str
    reason: str = ""
    severity: str = "high"
    command_id: str = ""
    expires_at: float | None = None
    created_at: float = field(default_factory=time.time)

    def normalized(self) -> "DynamicElement":
        if self.kind not in SET_FOR_KIND:
            raise ValueError(f"알 수 없는 동적 원소 종류: {self.kind}")
        if self.kind in {"mac", "admitted_mac"}:
            value = normalize_mac(self.value)
        elif self.kind in {"ipv4", "blocked_ipv4"}:
            value = check_address(self.value, 4)
        else:
            value = check_address(self.value, 6)
        return DynamicElement(self.kind, value, self.reason, self.severity, self.command_id,
                              self.expires_at, self.created_at)

    @property
    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)

    def expired(self, now: float | None = None) -> bool:
        return self.expires_at is not None and (now or time.time()) >= self.expires_at

    def timeout_spec(self, now: float | None = None) -> str:
        """nft 원소에 붙일 timeout 표현. 만료가 없으면 빈 문자열."""
        if self.expires_at is None:
            return ""
        remaining = int(self.expires_at - (now or time.time()))
        return f" timeout {max(1, remaining)}s"


class DynamicStore:
    def __init__(self, path: str | Path = DYNAMIC_FILE):
        self.path = Path(path)

    def load(self) -> list[DynamicElement]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        elements: list[DynamicElement] = []
        for item in raw.get("elements", []):
            try:
                elements.append(DynamicElement(**item).normalized())
            except (TypeError, ValueError) as exc:
                LOG.warning("동적 원소 무시: %s (%s)", item, exc)
        return elements

    def save(self, elements: Iterable[DynamicElement]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"updated_at": time.time(),
                   "elements": [asdict(element) for element in elements]}
        atomic_write(self.path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", 0o640)

    def replace(self, elements: Iterable[DynamicElement]) -> list[DynamicElement]:
        """중앙이 보낸 목록으로 전체 교체(desired state 방식)."""
        deduped: dict[tuple[str, str], DynamicElement] = {}
        for element in elements:
            normalized = element.normalized()
            if normalized.expired():
                continue
            deduped[normalized.key] = normalized
        result = sorted(deduped.values(), key=lambda e: (e.kind, e.value))
        self.save(result)
        return result

    def upsert(self, element: DynamicElement) -> list[DynamicElement]:
        current = {item.key: item for item in self.load()}
        normalized = element.normalized()
        current[normalized.key] = normalized
        result = sorted(current.values(), key=lambda e: (e.kind, e.value))
        self.save(result)
        return result

    def remove(self, kind: str, value: str) -> list[DynamicElement]:
        normalized = DynamicElement(kind, value).normalized()
        result = [item for item in self.load() if item.key != normalized.key]
        self.save(result)
        return result

    def prune(self) -> list[DynamicElement]:
        now = time.time()
        result = [item for item in self.load() if not item.expired(now)]
        self.save(result)
        return result


def _flush_and_add(runner: CommandRunner, family: str, table: str, set_name: str,
                   elements: list[DynamicElement]) -> tuple[bool, str]:
    script = [f"flush set {family} {table} {set_name}"]
    now = time.time()
    if elements:
        items = ", ".join(f"{element.value}{element.timeout_spec(now)}" for element in elements)
        script.append(f"add element {family} {table} {set_name} {{ {items} }}")
    result = runner.run(["nft", "-f", "-"], stdin="\n".join(script) + "\n", timeout=20.0)
    return result.ok, result.summary(200)


def sync(runner: CommandRunner, store: DynamicStore | None = None,
         elements: list[DynamicElement] | None = None) -> dict[str, Any]:
    """저장소 내용을 커널 셋과 일치시킨다.

    set 단위로 flush 후 일괄 추가한다. 원소를 하나씩 add/delete 하면 중간 상태가
    생기고, 중복/미존재 원소에서 오류가 나 전체가 멈춘다. flush+add는 nft 트랜잭션
    안에서 원자적이므로 그 문제가 없다.
    """
    store = store or DynamicStore()
    elements = elements if elements is not None else store.prune()
    grouped: dict[str, list[DynamicElement]] = {kind: [] for kind in SET_FOR_KIND}
    for element in elements:
        grouped[element.kind].append(element)

    report: dict[str, Any] = {"sets": [], "ok": True, "total": len(elements)}
    for kind, (family, table, set_name) in SET_FOR_KIND.items():
        ok, detail = _flush_and_add(runner, family, table, set_name, grouped[kind])
        report["sets"].append({"set": f"{family} {table} {set_name}",
                               "count": len(grouped[kind]), "ok": ok, "detail": detail})
        if not ok:
            report["ok"] = False

    # L2 격리는 bridge 테이블에도 같은 MAC 목록을 넣는다.
    family, table, set_name = BRIDGE_MAC_SET
    ok, detail = _flush_and_add(runner, family, table, set_name, grouped["mac"])
    report["sets"].append({"set": f"{family} {table} {set_name}", "count": len(grouped["mac"]),
                           "ok": ok, "detail": detail, "optional": True})
    if not ok:
        # bridge 테이블은 커널 지원이 없을 수 있다. L3 격리는 이미 반영됐으므로
        # 전체 실패로 보지 않되, 반드시 기록해 운영자가 알 수 있게 한다.
        LOG.warning("bridge 격리 셋 동기화 실패(L3 격리는 적용됨): %s", detail)

    LOG.info("동적 셋 동기화 ok=%s 원소=%d", report["ok"], len(elements))
    return report


def from_central_payload(payload: dict[str, Any]) -> list[DynamicElement]:
    """중앙 정책 응답의 quarantine/blocklist 블록을 동적 원소로 변환한다.

    기존 Agent가 쓰던 ``{"quarantine": [{"mac": ..., "expires_at": ...}]}`` 형식을
    그대로 받아들여, Router Plane 도입이 Agent 프로토콜 변경을 강제하지 않게 한다.
    """
    from datetime import datetime, timezone

    def parse_expiry(value: Any) -> float | None:
        if not value:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value)
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()

    elements: list[DynamicElement] = []
    for item in payload.get("quarantine", []) or []:
        if not isinstance(item, dict):
            continue
        expiry = parse_expiry(item.get("expires_at"))
        reason = str(item.get("reason", ""))[:255]
        command_id = str(item.get("command_id", ""))[:64]
        severity = str(item.get("severity", "high"))[:16]
        if item.get("mac"):
            elements.append(DynamicElement("mac", str(item["mac"]), reason, severity,
                                           command_id, expiry))
        for address in item.get("ip_addresses", []) or []:
            try:
                kind = "ipv4" if check_address(address, 4) else "ipv4"
            except ValueError:
                try:
                    check_address(address, 6)
                    kind = "ipv6"
                except ValueError:
                    continue
            elements.append(DynamicElement(kind, str(address), reason, severity,
                                           command_id, expiry))
    for item in payload.get("blocked_destinations", []) or []:
        if not isinstance(item, dict) or not item.get("address"):
            continue
        address = str(item["address"])
        try:
            check_address(address, 4)
            kind = "blocked_ipv4"
        except ValueError:
            try:
                check_address(address, 6)
                kind = "blocked_ipv6"
            except ValueError:
                continue
        elements.append(DynamicElement(kind, address, str(item.get("reason", ""))[:255],
                                       str(item.get("severity", "high"))[:16],
                                       str(item.get("command_id", ""))[:64],
                                       parse_expiry(item.get("expires_at"))))
    return elements
