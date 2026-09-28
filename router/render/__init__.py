"""정책 -> 설정/명령 컴파일러 모음.

각 렌더러는 (policy, ctx)를 받아 RenderPlan을 돌려주는 순수 함수다. 시스템을
직접 읽거나 쓰지 않으므로 root 없이 테스트할 수 있고, 같은 입력은 항상 같은
바이트열을 만든다(멱등 + 안정적 diff).

적용 순서가 곧 렌더러 등록 순서다.
  sysctl -> netplan -> networkd 드롭인 -> pppoe -> nftables -> kea -> unbound
  -> wireguard -> qos
커널 파라미터와 인터페이스가 먼저 서고, 그 위에 방화벽/서비스/QoS가 올라간다.
"""
from __future__ import annotations

from ..context import RenderContext
from ..model import RouterPolicy
from ..plan import RenderPlan
from . import kea, netplan, networkd, nftables, pppoe, qos, sysctl, unbound, wireguard

RENDERERS = (
    ("sysctl", sysctl.render),
    ("netplan", netplan.render),
    ("networkd", networkd.render),
    ("pppoe", pppoe.render),
    ("nftables", nftables.render),
    ("kea", kea.render),
    ("unbound", unbound.render),
    ("wireguard", wireguard.render),
    ("qos", qos.render),
)


def render_all(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    plan = RenderPlan()
    for name, renderer in RENDERERS:
        sub = renderer(policy, ctx)
        sub.notes = [f"[{name}] {note}" for note in sub.notes]
        plan.merge(sub)
    return plan.finalize()
