"""커널 파라미터. forwarding, rp_filter, conntrack 용량 등."""
from __future__ import annotations

from ..context import RenderContext
from ..model import RouterPolicy
from ..paths import SYSCTL_FILE
from ..plan import Command, FileTarget, RenderPlan, managed


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    lines = [
        "# 라우팅",
        f"net.ipv4.ip_forward = {1 if policy.ip_forward else 0}",
        f"net.ipv6.conf.all.forwarding = {1 if policy.ipv6_forward else 0}",
        "",
        "# 스푸핑 방지: 다회선/정책 라우팅에서는 loose(2)가 안전하다.",
        "net.ipv4.conf.all.rp_filter = 2",
        "net.ipv4.conf.default.rp_filter = 2",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.conf.all.send_redirects = 0",
        "net.ipv4.conf.all.accept_source_route = 0",
        "net.ipv6.conf.all.accept_redirects = 0",
        "",
        "# conntrack: 현장 단말 수 대비 여유를 둔다.",
        "net.netfilter.nf_conntrack_max = 262144",
        "net.netfilter.nf_conntrack_tcp_timeout_established = 7440",
        "",
        "# VRF/정책 라우팅에서 로컬 소켓이 올바른 테이블을 타게 한다.",
        "net.ipv4.tcp_l3mdev_accept = 1" if policy.vrfs else "# (VRF 미사용)",
        "net.ipv4.udp_l3mdev_accept = 1" if policy.vrfs else "",
        "",
        "# bridge 상에서 nftables가 IP 헤더를 보게 한다(격리 정책 정확도).",
        "net.bridge.bridge-nf-call-iptables = 1",
        "net.bridge.bridge-nf-call-ip6tables = 1",
    ]
    plan = RenderPlan(
        files=[FileTarget(SYSCTL_FILE, managed("\n".join(lines)), 0o644, "커널 파라미터")],
        apply_commands=[
            Command(("modprobe", "br_netfilter"), description="bridge netfilter 모듈", allow_fail=True),
            Command(("sysctl", "--system"), description="sysctl 재적용", timeout=20.0),
        ],
        required_binaries=["sysctl"],
    )
    return plan
