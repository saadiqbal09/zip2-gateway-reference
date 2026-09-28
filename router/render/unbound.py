"""Unbound 렌더러 (DNS forwarding + 도메인 보안 정책 + 질의 관측).

Unbound를 쓰는 이유는 세 가지다.
- forward-tls-upstream으로 상위 DNS 구간을 암호화할 수 있다(DoT).
- RPZ 존으로 대규모 차단 목록을 파일 하나로 관리하고 reload할 수 있다.
- dnstap 소켓으로 질의 메타데이터를 Agent가 구조적으로 수집할 수 있다.

차단 목록이 작을 때는 local-zone(always_nxdomain)을, 클 때는 RPZ 파일을 쓴다.
"""
from __future__ import annotations

import ipaddress

from ..context import RenderContext
from ..model import RouterPolicy
from ..paths import UNBOUND_BLOCK_FILE, UNBOUND_CONF_FILE, UNBOUND_RPZ_FILE, UNIT_UNBOUND
from ..plan import Command, FileTarget, RenderPlan, ServiceAction, managed

RPZ_THRESHOLD = 500


def _rpz_zone(policy: RouterPolicy) -> str:
    lines = [
        "$TTL 60",
        "@ IN SOA localhost. root.localhost. 1 3600 1200 604800 60",
        "  IN NS  localhost.",
        f"; revision={policy.revision} entries={len(policy.dns.blocked_domains)}",
    ]
    for domain in policy.dns.allowed_domains:
        lines.append(f"{domain} CNAME rpz-passthru.")
        lines.append(f"*.{domain} CNAME rpz-passthru.")
    for domain in policy.dns.blocked_domains:
        lines.append(f"{domain} CNAME .")
        lines.append(f"*.{domain} CNAME .")
    return "\n".join(lines) + "\n"


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    dns = policy.dns
    if not dns.enabled:
        return RenderPlan(notes=["DNS 비활성 (Unbound 미구성)"])

    listen_addresses: list[str] = ["127.0.0.1", "::1"]
    access_control: list[str] = ["127.0.0.0/8 allow", "::1 allow"]
    for segment in policy.dns_listen_segments:
        for cidr in segment.addresses:
            interface = ipaddress.ip_interface(cidr)
            listen_addresses.append(str(interface.ip))
            access_control.append(f"{interface.network} allow")

    use_rpz = ctx.unbound_supports_rpz and (
        len(dns.blocked_domains) >= RPZ_THRESHOLD or bool(dns.rpz_zones))

    server: list[str] = [
        "server:",
        "    # Mooker 관리 구간",
        "    verbosity: 1",
        "    do-ip4: yes",
        "    do-ip6: yes",
        "    do-udp: yes",
        "    do-tcp: yes",
        "    prefer-ip6: no",
        "    hide-identity: yes",
        "    hide-version: yes",
        "    harden-glue: yes",
        "    harden-dnssec-stripped: yes",
        "    harden-below-nxdomain: yes",
        "    qname-minimisation: yes",
        "    aggressive-nsec: yes",
        f"    minimal-responses: {'yes' if dns.minimal_responses else 'no'}",
        f"    msg-cache-size: {max(1, dns.cache_max_mb // 4)}m",
        f"    rrset-cache-size: {dns.cache_max_mb}m",
        "    cache-min-ttl: 60",
        "    cache-max-negative-ttl: 60",
        "    num-threads: 2",
        "    so-reuseport: yes",
        "    # 스푸핑 방지",
        "    unwanted-reply-threshold: 10000000",
        "    val-clean-additional: yes",
        "",
        "    # 리스닝: 루프백과 정책이 지정한 세그먼트 주소만",
    ]
    for address in dict.fromkeys(listen_addresses):
        server.append(f"    interface: {address}")
    server.append("")
    server.append("    # 접근 제어: 정책에 없는 대역은 refuse")
    for entry in dict.fromkeys(access_control):
        server.append(f"    access-control: {entry}")
    server.append("    access-control: 0.0.0.0/0 refuse")
    server.append("    access-control: ::/0 refuse")
    server.append("")

    if dns.log_queries:
        server.extend([
            "    # 질의 로깅: syslog 부하가 크므로 조사 기간에만 켠다.",
            "    log-queries: yes",
            "    log-replies: yes",
            "    log-tag-queryreply: yes",
            "",
        ])
    if not use_rpz and dns.blocked_domains:
        server.append("    # 차단 도메인 (소규모: local-zone)")
        for domain in dns.blocked_domains:
            server.append(f'    local-zone: "{domain}." always_nxdomain')
        server.append("")
    if dns.allowed_domains and not use_rpz:
        server.append("    # 예외 허용 도메인은 차단 목록보다 우선한다.")
        for domain in dns.allowed_domains:
            server.append(f'    local-zone: "{domain}." transparent')
        server.append("")

    server.extend([
        "    # 로컬 컨트롤: Agent가 통계/차단 목록 reload를 수행한다.",
        "remote-control:",
        "    control-enable: yes",
        "    control-interface: /run/unbound.ctl",
        "    control-use-cert: no",
        "",
    ])

    if dns.dnstap_socket:
        server.extend([
            "dnstap:",
            "    dnstap-enable: yes",
            f"    dnstap-socket-path: {dns.dnstap_socket}",
            "    dnstap-send-identity: yes",
            "    dnstap-log-client-query-messages: yes",
            "    dnstap-log-client-response-messages: yes",
            "",
        ])

    if use_rpz:
        server.extend([
            "rpz:",
            "    name: mooker.rpz.",
            f"    zonefile: {UNBOUND_RPZ_FILE}",
            "    rpz-action-override: nxdomain",
            "    rpz-log: yes",
            "    rpz-log-name: mooker-rpz",
            "",
        ])

    forward = ["forward-zone:", '    name: "."']
    if dns.forward_tls:
        forward.append("    forward-tls-upstream: yes")
    for index, address in enumerate(dns.forwarders):
        if dns.forward_tls:
            hostname = dns.forward_tls_hostnames[index] if index < len(dns.forward_tls_hostnames) else ""
            suffix = f"@853#{hostname}" if hostname else "@853"
            forward.append(f"    forward-addr: {address}{suffix}")
        else:
            forward.append(f"    forward-addr: {address}")
    forward.append("")

    content = managed("\n".join(server + forward))

    files = [FileTarget(UNBOUND_CONF_FILE, content, 0o644, "Unbound DNS 정책")]
    if use_rpz:
        files.append(FileTarget(UNBOUND_RPZ_FILE, _rpz_zone(policy), 0o644,
                                f"RPZ 차단 존 ({len(dns.blocked_domains)} 항목)"))
    notes = []
    if len(dns.blocked_domains) >= RPZ_THRESHOLD and not ctx.unbound_supports_rpz:
        notes.append(
            "Unbound 버전이 RPZ를 지원하지 않아 대규모 차단 목록을 local-zone으로 생성했다. "
            "설정 파일이 커지고 reload가 느려지므로 Unbound 1.17 이상으로 올리는 것을 권장한다.")

    return RenderPlan(
        files=files,
        precheck=[
            Command(("unbound-checkconf", UNBOUND_CONF_FILE),
                    description="Unbound 설정 검증", stage_root_placeholder="@STAGE_FILE@",
                    timeout=60.0),
        ],
        services=[ServiceAction(UNIT_UNBOUND, "restart", description="DNS 정책 반영")],
        managed_paths=[UNBOUND_CONF_FILE, UNBOUND_BLOCK_FILE, UNBOUND_RPZ_FILE],
        notes=notes,
        required_binaries=["unbound-checkconf"],
    )
