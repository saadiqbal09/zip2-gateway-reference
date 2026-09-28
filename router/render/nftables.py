"""nftables 렌더러.

두 개의 테이블만 소유한다.

``table inet mooker``     : L3 방화벽(zone 매트릭스), NAT, 관리 접근, 검역
``table bridge mooker_l2``: L2 검역(같은 세그먼트 내 통신 차단), rogue DHCP 차단

원칙
- 고객이 이미 쓰고 있는 다른 nftables 테이블은 건드리지 않는다. 전체
  ``flush ruleset``을 절대 쓰지 않고, ``table ...; delete table ...; table ... {}``
  관용구로 우리 테이블만 원자적으로 교체한다.
- 동적 검역 원소(MAC/IP)는 named set에 timeout으로 넣는다. 정책 재적용 시 set이
  비므로, 적용 직후 ``mooker-router restore-dynamic``이 마지막 원소를 되살린다.
- output chain은 policy accept를 유지한다. 잘못된 정책이 중앙 제어 채널을
  스스로 끊어버리는 사고를 구조적으로 막는다(보안 baseline).
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from ..context import RenderContext
from ..model import RouterPolicy
from ..paths import (NFT_BRIDGE_FILE, NFT_DIR, NFT_INET_FILE,
                     RESTORE_DYNAMIC_HELPER, UNIT_NFTABLES)
from ..plan import Command, FileTarget, RenderPlan, ServiceAction, managed

TABLE_INET = "inet mooker"
TABLE_BRIDGE = "bridge mooker_l2"

SET_QUARANTINE_MAC = "quarantine_mac"
SET_QUARANTINE_V4 = "quarantine_v4"
SET_QUARANTINE_V6 = "quarantine_v6"
SET_BLOCKED_V4 = "blocked_dst_v4"
SET_BLOCKED_V6 = "blocked_dst_v6"
SET_MGMT_V4 = "mgmt_allow_v4"
SET_MGMT_V6 = "mgmt_allow_v6"
SET_ADMITTED_MAC = "admitted_mac"


def _quote_list(values: Iterable[str]) -> str:
    return "{ " + ", ".join(f'"{value}"' for value in sorted(set(values))) + " }"


def _plain_list(values: Iterable[str]) -> str:
    return "{ " + ", ".join(str(value) for value in values) + " }"


def _zone_interfaces(policy: RouterPolicy, zone: str) -> tuple[str, ...]:
    if zone == policy.wan_zone:
        return tuple(sorted({link.link_interface for link in policy.wan_links}))
    return tuple(sorted({segment.interface for segment in policy.segments_in_zone(zone)}))


def _split_networks(cidrs: Iterable[str]) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr)
        (v4 if network.version == 4 else v6).append(str(network))
    return v4, v6


def _inet_ruleset(policy: RouterPolicy) -> str:
    firewall = policy.firewall
    lines: list[str] = []
    add = lines.append

    add(f"# tenant={policy.tenant} site={policy.site} revision={policy.revision}")
    add("")
    add("table inet mooker")
    add("delete table inet mooker")
    add("table inet mooker {")

    # ---------------- named sets ----------------
    mgmt_v4, mgmt_v6 = _split_networks(firewall.mgmt_allow_cidrs)
    add("    # 중앙/Agent가 원소만 갱신하는 동적 셋. 정책 재적용 시 비므로 restore-dynamic이 되살린다.")
    add(f"    set {SET_QUARANTINE_MAC} {{")
    add("        type ether_addr")
    add("        flags timeout")
    add("        comment \"즉시 격리 대상 MAC\"")
    add("    }")
    for name, addr_type, comment in (
        (SET_QUARANTINE_V4, "ipv4_addr", "격리 대상 IPv4"),
        (SET_QUARANTINE_V6, "ipv6_addr", "격리 대상 IPv6"),
        (SET_BLOCKED_V4, "ipv4_addr", "차단 목적지 IPv4 (위협 인텔리전스)"),
        (SET_BLOCKED_V6, "ipv6_addr", "차단 목적지 IPv6 (위협 인텔리전스)"),
    ):
        add(f"    set {name} {{")
        add(f"        type {addr_type}")
        add("        flags interval, timeout")
        add(f"        comment \"{comment}\"")
        add("    }")
    add(f"    set {SET_ADMITTED_MAC} {{")
    add("        type ether_addr")
    add("        flags timeout")
    add("        comment \"승인 단말 MAC (allow-list 모드에서 사용)\"")
    add("    }")
    for name, addr_type, elements, comment in (
        (SET_MGMT_V4, "ipv4_addr", mgmt_v4, "관리 접근 허용 IPv4 대역"),
        (SET_MGMT_V6, "ipv6_addr", mgmt_v6, "관리 접근 허용 IPv6 대역"),
    ):
        add(f"    set {name} {{")
        add(f"        type {addr_type}")
        add("        flags interval")
        add(f"        comment \"{comment}\"")
        if elements:
            add(f"        elements = {_plain_list(elements)}")
        add("    }")
    add("")

    # ---------------- 로그/폐기 보조 체인 ----------------
    add("    chain log_drop {")
    if firewall.log_dropped:
        add('        limit rate 5/second burst 10 packets log prefix "mooker-drop " level info')
    add("        counter drop")
    add("    }")
    add("")
    # 격리 게이트는 방향별로 다르다. Gateway 자신에게 오는 트래픽(input)은 주소 획득과
    # 이름 해석, 안내 페이지까지 허용하지만, 통과 트래픽(forward)은 전부 막는다.
    # 하나의 체인을 공유하면 격리 단말이 외부 DNS로 나가는 경로가 열려버린다.
    add("    chain quarantine_input {")
    if firewall.quarantine_allow_dhcp_dns:
        add('        udp dport { 67, 68 } counter accept comment "주소 획득"')
        add('        meta l4proto { tcp, udp } th dport 53 counter accept comment "이름 해석"')
    if firewall.captive_portal_ipv4:
        add(f'        ip daddr {firewall.captive_portal_ipv4} tcp dport {{ 80, 443 }} '
            f'counter accept comment "격리 안내 페이지"')
    add('        limit rate 2/second burst 5 packets log prefix "mooker-quarantine-in " level warn')
    add("        counter drop")
    add("    }")
    add("")
    add("    chain quarantine_forward {")
    add("        # 격리 단말의 통과 트래픽은 예외 없이 폐기한다.")
    add('        limit rate 2/second burst 5 packets log prefix "mooker-quarantine-fw " level warn')
    add("        counter drop")
    add("    }")
    add("")

    # ---------------- input ----------------
    add("    chain input {")
    add("        type filter hook input priority filter; policy drop;")
    add('        iif lo counter accept comment "loopback"')
    add("        # 격리는 기존 세션보다 먼저 판정한다. 그래야 즉시 효력이 생긴다.")
    add(f"        ether saddr @{SET_QUARANTINE_MAC} counter jump quarantine_input")
    add(f"        ip saddr @{SET_QUARANTINE_V4} counter jump quarantine_input")
    add(f"        ip6 saddr @{SET_QUARANTINE_V6} counter jump quarantine_input")
    add("        ct state established,related counter accept")
    if firewall.invalid_ct_drop:
        add("        ct state invalid counter drop")
    add("        # 진단에 필요한 ICMP만 통과시킨다.")
    add("        icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } "
        "limit rate 20/second counter accept")
    add("        icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, "
        "parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, "
        "mld-listener-query, mld-listener-report } counter accept")

    dhcp_ifaces = sorted({segment.interface for segment in policy.dhcp_segments})
    dns_ifaces = sorted({segment.interface for segment in policy.dns_listen_segments})
    dhcp_client_ifaces = sorted({link.link_interface for link in policy.wan_links
                                 if link.mode == "dhcp4"})
    if dhcp_client_ifaces:
        add(f"        iifname {_quote_list(dhcp_client_ifaces)} udp sport 67 udp dport 68 "
            f'counter accept comment "WAN DHCP 클라이언트 응답"')
    if dhcp_ifaces:
        add(f"        iifname {_quote_list(dhcp_ifaces)} udp dport 67 counter accept "
            f'comment "DHCP 서버"')
    if dns_ifaces and policy.dns.enabled:
        add(f"        iifname {_quote_list(dns_ifaces)} meta l4proto {{ tcp, udp }} th dport 53 "
            f'counter accept comment "로컬 DNS"')
    if any(segment.ipv6_ra for segment in policy.lans):
        ra_ifaces = sorted({s.interface for s in policy.lans if s.ipv6_ra})
        add(f"        iifname {_quote_list(ra_ifaces)} udp dport 547 counter accept "
            f'comment "DHCPv6"')

    add("        # 관리 접근: 명시된 대역에서만, 속도 제한과 함께 허용한다.")
    if mgmt_v4:
        # 무차별 접속 시도는 'limit rate over'로 걸러내고, 통과한 것만 허용한다.
        add(f"        ip saddr @{SET_MGMT_V4} tcp dport {firewall.mgmt_ssh_port} ct state new "
            f"limit rate over 10/minute burst 5 packets counter jump log_drop")
        add(f"        ip saddr @{SET_MGMT_V4} tcp dport {firewall.mgmt_ssh_port} counter accept")
    if mgmt_v6:
        add(f"        ip6 saddr @{SET_MGMT_V6} tcp dport {firewall.mgmt_ssh_port} ct state new "
            f"limit rate over 10/minute burst 5 packets counter jump log_drop")
        add(f"        ip6 saddr @{SET_MGMT_V6} tcp dport {firewall.mgmt_ssh_port} counter accept")
    if policy.mgmt_tunnel.enabled:
        add(f'        iifname "{policy.mgmt_tunnel.interface}" counter accept '
            f'comment "중앙 관리 터널 내부"')

    for allow in firewall.service_allows:
        ifaces = _zone_interfaces(policy, allow.zone)
        if not ifaces:
            continue
        source = ""
        if allow.source_cidrs:
            v4, v6 = _split_networks(allow.source_cidrs)
            if v4:
                add(f"        iifname {_quote_list(ifaces)} ip saddr {_plain_list(v4)} "
                    f"{allow.protocol} dport {_plain_list(allow.ports)} counter accept "
                    f'comment "{allow.comment or allow.zone}"')
            if v6:
                add(f"        iifname {_quote_list(ifaces)} ip6 saddr {_plain_list(v6)} "
                    f"{allow.protocol} dport {_plain_list(allow.ports)} counter accept "
                    f'comment "{allow.comment or allow.zone}"')
            continue
        add(f"        iifname {_quote_list(ifaces)} {allow.protocol} dport "
            f"{_plain_list(allow.ports)} counter accept {source}"
            f'comment "{allow.comment or allow.zone}"')
    add("        jump log_drop")
    add("    }")
    add("")

    # ---------------- forward ----------------
    add("    chain forward {")
    add(f"        type filter hook forward priority filter; policy {firewall.default_forward};")
    add("        # 1) 격리 우선")
    add(f"        ether saddr @{SET_QUARANTINE_MAC} counter jump quarantine_forward")
    add(f"        ip saddr @{SET_QUARANTINE_V4} counter jump quarantine_forward")
    add(f"        ip daddr @{SET_QUARANTINE_V4} counter jump quarantine_forward")
    add(f"        ip6 saddr @{SET_QUARANTINE_V6} counter jump quarantine_forward")
    add(f"        ip6 daddr @{SET_QUARANTINE_V6} counter jump quarantine_forward")
    if firewall.mss_clamp:
        add("        # 2) PPPoE/터널 경로의 MTU 문제를 없앤다.")
        add("        tcp flags syn tcp option maxseg size set rt mtu")
    add("        # 3) 위협 인텔리전스 목적지 차단")
    add(f"        ip daddr @{SET_BLOCKED_V4} counter jump log_drop")
    add(f"        ip6 daddr @{SET_BLOCKED_V6} counter jump log_drop")
    add("        # 4) 세그먼트 내부 격리(라우팅 경로). L2는 bridge 테이블이 담당한다.")
    for segment in policy.lans:
        if segment.client_isolation:
            add(f'        iifname "{segment.interface}" oifname "{segment.interface}" '
                f'counter jump log_drop comment "client isolation {segment.name}"')
    add("        # 5) 명시 규칙이 zone 매트릭스보다 우선한다.")
    for rule in firewall.forward_rules:
        in_ifaces = _zone_interfaces(policy, rule.from_zone)
        out_ifaces = _zone_interfaces(policy, rule.to_zone)
        if not in_ifaces or not out_ifaces:
            continue
        parts = [f"iifname {_quote_list(in_ifaces)}", f"oifname {_quote_list(out_ifaces)}"]
        v4, v6 = _split_networks(rule.source_cidrs)
        dv4, dv6 = _split_networks(rule.destination_cidrs)
        families: list[list[str]] = []
        if v4 or dv4 or (not rule.source_cidrs and not rule.destination_cidrs):
            family = list(parts)
            if v4:
                family.append(f"ip saddr {_plain_list(v4)}")
            if dv4:
                family.append(f"ip daddr {_plain_list(dv4)}")
            families.append(family)
        if v6 or dv6:
            family = list(parts)
            if v6:
                family.append(f"ip6 saddr {_plain_list(v6)}")
            if dv6:
                family.append(f"ip6 daddr {_plain_list(dv6)}")
            families.append(family)
        for family in families:
            if rule.protocol == "icmp":
                family.append("meta l4proto { icmp, ipv6-icmp }")
            elif rule.protocol in {"tcp", "udp"}:
                family.append(rule.protocol)
                if rule.ports:
                    family.append(f"dport {_plain_list(rule.ports)}")
            body = " ".join(family)
            if rule.log and rule.action != "accept":
                add(f"        {body} counter jump log_drop comment \"{rule.name}\"")
            elif rule.action == "reject":
                add(f"        {body} counter reject with icmpx type admin-prohibited "
                    f"comment \"{rule.name}\"")
            else:
                add(f"        {body} counter {rule.action} comment \"{rule.name}\"")
    add("        # 6) 상태 기반 통과와 DNAT 세션")
    add("        ct state established,related counter accept")
    if firewall.invalid_ct_drop:
        add("        ct state invalid counter drop")
    if firewall.port_forwards:
        add("        ct status dnat counter accept comment \"port forward 세션\"")
    add("        # 7) zone 매트릭스")
    for src_zone, dst_zone in firewall.zone_forward:
        in_ifaces = _zone_interfaces(policy, src_zone)
        out_ifaces = _zone_interfaces(policy, dst_zone)
        if not in_ifaces or not out_ifaces:
            continue
        add(f"        iifname {_quote_list(in_ifaces)} oifname {_quote_list(out_ifaces)} "
            f'counter accept comment "{src_zone}->{dst_zone}"')
    add("        jump log_drop")
    add("    }")
    add("")

    # ---------------- output ----------------
    add("    chain output {")
    add("        # 정책이 중앙 제어 채널을 스스로 끊는 사고를 막기 위해 accept를 유지한다.")
    add("        type filter hook output priority filter; policy accept;")
    add("        counter")
    add("    }")
    add("")

    # ---------------- NAT ----------------
    add("    chain dstnat {")
    add("        type nat hook prerouting priority dstnat; policy accept;")
    for forward in firewall.port_forwards:
        link = policy.wan(forward.wan)
        source = ""
        if forward.source_cidrs:
            v4, _ = _split_networks(forward.source_cidrs)
            if v4:
                source = f"ip saddr {_plain_list(v4)} "
        target = ipaddress.ip_address(forward.to_address)
        keyword = "dnat ip to" if target.version == 4 else "dnat ip6 to"
        destination = f"{forward.to_address}:{forward.to_port}" if target.version == 4 else \
            f"[{forward.to_address}]:{forward.to_port}"
        add(f'        iifname "{link.link_interface}" {source}{forward.protocol} dport '
            f"{forward.wan_port} counter {keyword} {destination} "
            f'comment "{forward.name}"')
    add("    }")
    add("")
    add("    chain srcnat {")
    add("        type nat hook postrouting priority srcnat; policy accept;")
    for name in firewall.masquerade_wans:
        link = policy.wan(name)
        add(f'        oifname "{link.link_interface}" counter masquerade '
            f'comment "NAT {name}"')
    # 헤어핀 NAT: 내부에서 공인 포트로 접근할 때 응답 경로를 보장한다.
    for forward in firewall.port_forwards:
        target = ipaddress.ip_address(forward.to_address)
        if target.version != 4:
            continue
        for segment in policy.lans:
            gateway_ip = segment.gateway_ipv4
            if gateway_ip is None:
                continue
            network = None
            for cidr in segment.addresses:
                interface = ipaddress.ip_interface(cidr)
                if interface.version == 4:
                    network = interface.network
                    break
            if network is None or ipaddress.ip_address(forward.to_address) not in network:
                continue
            add(f'        oifname "{segment.interface}" ip saddr {network} ip daddr '
                f"{forward.to_address} {forward.protocol} dport {forward.to_port} counter "
                f"snat ip to {gateway_ip} comment \"hairpin {forward.name}\"")
    add("    }")
    add("}")
    return managed("\n".join(lines) + "\n")


def _bridge_ruleset(policy: RouterPolicy) -> str:
    lines: list[str] = []
    add = lines.append
    add("# L2 검역: 라우터를 거치지 않는 같은 세그먼트 내부 통신까지 차단한다.")
    add("table bridge mooker_l2")
    add("delete table bridge mooker_l2")
    add("table bridge mooker_l2 {")
    add(f"    set {SET_QUARANTINE_MAC} {{")
    add("        type ether_addr")
    add("        flags timeout")
    add("        comment \"격리 대상 MAC (L2)\"")
    add("    }")
    add("")
    add("    chain forward {")
    add("        type filter hook forward priority filter; policy accept;")
    add(f"        ether saddr @{SET_QUARANTINE_MAC} counter drop")
    add(f"        ether daddr @{SET_QUARANTINE_MAC} counter drop")
    rogue_ports: list[str] = []
    for bridge in policy.bridges:
        if bridge.drop_rogue_dhcp:
            rogue_ports.extend(bridge.ports)
    if rogue_ports:
        add("        # rogue DHCP 서버 차단: LAN 포트에서 들어오는 DHCP 응답은 폐기한다.")
        add(f"        iifname {_quote_list(rogue_ports)} ether type ip udp sport 67 "
            f'counter drop comment "rogue DHCPv4"')
        add(f"        iifname {_quote_list(rogue_ports)} ether type ip6 udp sport 547 "
            f'counter drop comment "rogue DHCPv6"')
    add("    }")
    add("}")
    return managed("\n".join(lines) + "\n")


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    inet_content = _inet_ruleset(policy)
    bridge_content = _bridge_ruleset(policy)
    return RenderPlan(
        files=[
            FileTarget(NFT_INET_FILE, inet_content, 0o640, "nftables inet mooker (L3/NAT/관리/검역)"),
            FileTarget(NFT_BRIDGE_FILE, bridge_content, 0o640, "nftables bridge mooker_l2 (L2 검역)"),
        ],
        precheck=[
            Command(("nft", "-c", "-f", NFT_INET_FILE), description="nftables inet 문법 검증",
                    stage_root_placeholder="@STAGE_FILE@", timeout=20.0),
            Command(("nft", "-c", "-f", NFT_BRIDGE_FILE), description="nftables bridge 문법 검증",
                    stage_root_placeholder="@STAGE_FILE@", timeout=20.0),
        ],
        apply_commands=[
            Command(("nft", "-f", NFT_INET_FILE), description="inet mooker 원자 교체", timeout=30.0),
            Command(("nft", "-f", NFT_BRIDGE_FILE), description="bridge mooker_l2 원자 교체",
                    timeout=30.0, allow_fail=not ctx.have_bridge_nft),
            Command((RESTORE_DYNAMIC_HELPER,),
                    description="정책 교체로 비워진 검역/차단 셋 원소 복원",
                    timeout=30.0, allow_fail=True),
        ],
        services=[ServiceAction(UNIT_NFTABLES, "enable",
                               description="부팅 시 mooker 테이블 재적용")],
        owned_globs=[f"{NFT_DIR}/*.nft"],
        notes=[
            "bridge 테이블은 br_netfilter/nf_tables bridge 지원이 없으면 실패할 수 있어 allow_fail로 둔다."
            " 실패 시 L3 격리만 동작하고 같은 세그먼트 내부 통신은 networkd Isolated= 설정에 의존한다.",
            "WireGuard 관리 터널은 outbound로만 개시하므로 WAN에 인바운드 포트를 열지 않는다.",
        ],
        required_binaries=["nft"],
    )
