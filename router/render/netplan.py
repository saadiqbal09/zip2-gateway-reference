"""Netplan 렌더러 (renderer: networkd).

Ubuntu 24.04의 표준 경로를 그대로 쓴다. 하나의 파일 ``90-mooker.yaml``만 소유하고,
고객이 넣어둔 다른 netplan 파일은 손대지 않는다(파일명 접두어 90으로 우선순위를
확보한다).

netplan이 직접 표현하지 못하는 두 가지는 다른 렌더러가 맡는다.
- bridge VLAN filtering / 포트별 PVID  -> render/networkd.py (systemd-networkd 드롭인)
- PPPoE                                -> render/pppoe.py (pppd + systemd 유닛)
"""
from __future__ import annotations

import ipaddress
from typing import Any

from ..context import RenderContext
from ..model import LanSegment, RouterPolicy
from ..paths import NETPLAN_FILE
from ..plan import Command, FileTarget, RenderPlan, managed
from ..util import yaml_dump


def _wan_ethernet(link) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    if link.mode == "dhcp4":
        entry["dhcp4"] = True
        entry["dhcp6"] = False
        entry["dhcp4-overrides"] = {
            "route-metric": link.metric,
            # 로컬 Unbound가 유일한 resolver다. ISP DNS를 시스템에 밀어넣지 않는다.
            "use-dns": False,
            "use-domains": False,
        }
    elif link.mode == "static":
        entry["dhcp4"] = False
        entry["dhcp6"] = False
        entry["addresses"] = list(link.addresses)
        routes: list[dict[str, Any]] = []
        if link.gateway4:
            route: dict[str, Any] = {"to": "default", "via": link.gateway4, "metric": link.metric}
            if link.table:
                route["table"] = link.table
            routes.append(route)
        if link.gateway6:
            route6: dict[str, Any] = {"to": "default", "via": link.gateway6, "metric": link.metric}
            if link.table:
                route6["table"] = link.table
            routes.append(route6)
        if routes:
            entry["routes"] = routes
        if link.table:
            # 정책 라우팅: 이 회선의 소스 주소는 이 회선 테이블을 탄다.
            rules = []
            for cidr in link.addresses:
                interface = ipaddress.ip_interface(cidr)
                rules.append({"from": str(interface.ip), "table": link.table, "priority": 10000 + link.table})
            entry["routing-policy"] = rules
    else:  # pppoe: 물리 인터페이스는 L2 반송만 담당한다.
        entry["dhcp4"] = False
        entry["dhcp6"] = False
        entry["link-local"] = []
    entry["accept-ra"] = bool(link.accept_ra)
    if link.mtu:
        entry["mtu"] = link.mtu
    if not link.required_for_online:
        entry["optional"] = True
    return entry


def _addresses_for_device(policy: RouterPolicy, device: str) -> LanSegment | None:
    for segment in policy.lans:
        if segment.interface == device:
            return segment
    return None


def _apply_segment(entry: dict[str, Any], segment: LanSegment | None) -> dict[str, Any]:
    if segment is None:
        return entry
    entry["addresses"] = list(segment.addresses)
    entry["dhcp4"] = False
    entry["dhcp6"] = False
    entry["accept-ra"] = False
    if segment.mtu:
        entry["mtu"] = segment.mtu
    if segment.vrf:
        # netplan은 vrfs.<name>.interfaces 쪽에서 소속을 표현한다. 여기서는 주석용.
        pass
    return entry


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ethernets: dict[str, Any] = {}
    bridges: dict[str, Any] = {}
    vlans: dict[str, Any] = {}
    vrfs: dict[str, Any] = {}
    notes: list[str] = []

    bridge_names = {bridge.name for bridge in policy.bridges}
    bridge_ports = {port for bridge in policy.bridges for port in bridge.ports}

    # 1) WAN 물리 인터페이스
    for link in policy.wan_links:
        ethernets[link.interface] = _wan_ethernet(link)
        if link.mode == "dhcp4" and link.table:
            notes.append(
                f"WAN '{link.name}'은 DHCP + table {link.table} 구성이다. DHCP로 받은 소스 주소 기반 "
                f"routing-policy는 부팅 시점에 알 수 없으므로 Agent의 다회선 모듈이 주소 획득 후 "
                f"규칙을 채운다(netplan에는 metric만 반영된다).")

    # 2) 브리지 포트 (L3 없음)
    for port in sorted(bridge_ports):
        if port in ethernets:
            continue
        ethernets[port] = {"dhcp4": False, "dhcp6": False, "accept-ra": False,
                           "link-local": [], "optional": True}

    # 3) 브리지
    for bridge in policy.bridges:
        entry: dict[str, Any] = {
            "interfaces": list(bridge.ports),
            "dhcp4": False,
            "dhcp6": False,
            "accept-ra": False,
            "parameters": {"stp": bridge.stp, "forward-delay": 4 if bridge.stp else 0},
        }
        _apply_segment(entry, _addresses_for_device(policy, bridge.name))
        bridges[bridge.name] = entry

    # 4) LAN segment 디바이스
    for segment in policy.lans:
        if segment.vlan_id is not None:
            entry = {"id": segment.vlan_id, "link": segment.vlan_link}
            vlans[segment.interface] = _apply_segment(entry, segment)
            continue
        if segment.interface in bridge_names:
            continue  # 이미 bridges에서 주소를 부여했다
        entry = {"dhcp4": False, "dhcp6": False, "accept-ra": False, "optional": True}
        ethernets.setdefault(segment.interface, {})
        ethernets[segment.interface].update(_apply_segment(entry, segment))

    # 5) VRF
    for vrf in policy.vrfs:
        members = list(vrf.interfaces) or [s.interface for s in policy.lans if s.vrf == vrf.name]
        vrfs[vrf.name] = {"table": vrf.table, "interfaces": sorted(set(members))}

    document: dict[str, Any] = {"network": {"version": 2, "renderer": "networkd"}}
    if ethernets:
        document["network"]["ethernets"] = dict(sorted(ethernets.items()))
    if bridges:
        document["network"]["bridges"] = dict(sorted(bridges.items()))
    if vlans:
        document["network"]["vlans"] = dict(sorted(vlans.items()))
    if vrfs:
        document["network"]["vrfs"] = dict(sorted(vrfs.items()))

    header = managed(
        f"# tenant={policy.tenant} site={policy.site} revision={policy.revision}\n"
    )
    content = header + yaml_dump(document) + "\n"

    return RenderPlan(
        files=[FileTarget(NETPLAN_FILE, content, 0o600, "netplan (WAN/LAN/bridge/VLAN/VRF)")],
        precheck=[
            Command(("netplan", "generate", "--root-dir", "@STAGE@"),
                    description="netplan 문법/의미 검증 (staging 루트, 시스템 미변경)",
                    timeout=60.0, stage_root_placeholder="@STAGE@"),
        ],
        apply_commands=[
            Command(("netplan", "generate"), description="networkd 설정 생성", timeout=60.0),
            Command(("netplan", "apply"), description="네트워크 설정 적용", timeout=90.0),
        ],
        managed_paths=[NETPLAN_FILE],
        notes=notes,
        required_binaries=["netplan", "ip"],
    )
