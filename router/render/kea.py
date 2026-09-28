"""Kea DHCPv4 렌더러.

Ubuntu 24.04의 ``kea-dhcp4-server`` 패키지를 그대로 쓴다. 설정은 JSON이므로
프로그램적으로 생성/검증하기 쉽고, ``kea-dhcp4 -t <file>``로 적용 전에 문법과
스키마를 확인할 수 있다.

reservation은 정책의 desired state에서 온다. 현장에서 즉흥적으로 lease를 바꾸는
경로는 두지 않는다. 다만 lease 조회/삭제 같은 운영 동작은 control socket
(lease_cmds hook)으로 처리한다.
"""
from __future__ import annotations

import json

from ..context import RenderContext
from ..model import LanSegment, RouterPolicy
from ..paths import KEA_CTRL_SOCKET, KEA_DHCP4_FILE, UNIT_KEA4
from ..plan import Command, FileTarget, RenderPlan, ServiceAction

LEASE_DB = "/var/lib/kea/kea-leases4.csv"


def _option_data(segment: LanSegment, scope) -> list[dict[str, str]]:
    gateway = segment.gateway_ipv4
    routers = list(scope.routers) or ([gateway] if gateway else [])
    dns = list(scope.dns) or ([gateway] if gateway else [])
    options: list[dict[str, str]] = []
    if routers:
        options.append({"name": "routers", "data": ", ".join(routers)})
    if dns:
        options.append({"name": "domain-name-servers", "data": ", ".join(dns)})
    if scope.domain_name:
        options.append({"name": "domain-name", "data": scope.domain_name})
        options.append({"name": "domain-search", "data": scope.domain_name})
    if scope.ntp_servers:
        options.append({"name": "ntp-servers", "data": ", ".join(scope.ntp_servers)})
    return options


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    segments = policy.dhcp_segments
    if not segments:
        return RenderPlan(notes=["DHCP scope 없음 (Kea 미구성)"])

    interfaces: list[str] = []
    subnets: list[dict] = []
    for index, segment in enumerate(segments, start=1):
        scope = segment.dhcp
        assert scope is not None
        gateway = segment.gateway_ipv4
        interfaces.append(f"{segment.interface}/{gateway}" if gateway else segment.interface)
        pool = {"pool": f"{scope.pool_start} - {scope.pool_end}"}
        if not scope.unknown_clients_allowed:
            # Kea 관용구: KNOWN 클래스만 동적 pool을 쓸 수 있다.
            # 미등록 단말은 주소를 받지 못하므로 별도 quarantine SSID/VLAN을 병행한다.
            pool["client-class"] = "KNOWN"
        reservations = [
            {
                "hw-address": res.mac.lower(),
                "ip-address": res.ip,
                **({"hostname": res.hostname} if res.hostname else {}),
            }
            for res in scope.reservations
        ]
        subnets.append(
            {
                "id": index,
                "subnet": scope.subnet,
                "interface": segment.interface,
                "pools": [pool],
                "valid-lifetime": scope.lease_lifetime_s,
                "option-data": _option_data(segment, scope),
                "reservations-global": False,
                "reservations-in-subnet": True,
                "reservations-out-of-pool": True,
                "reservations": reservations,
                "user-context": {
                    "mooker-segment": segment.name,
                    "mooker-zone": segment.zone,
                    "mooker-vlan": segment.vlan_id,
                },
            }
        )

    hooks: list[dict] = []
    if ctx.kea_hooks_library:
        hooks.append({"library": ctx.kea_hooks_library})

    document = {
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": interfaces,
                # raw 소켓은 브리지/VLAN 조합에서 예상 밖으로 동작할 수 있다.
                "dhcp-socket-type": "udp",
                "service-sockets-max-retries": 5,
                "service-sockets-retry-wait-time": 5000,
            },
            "control-socket": {"socket-type": "unix", "socket-name": KEA_CTRL_SOCKET},
            "lease-database": {
                "type": "memfile",
                "persist": True,
                "name": LEASE_DB,
                "lfc-interval": 3600,
            },
            "expired-leases-processing": {
                "reclaim-timer-wait-time": 10,
                "hold-reclaimed-time": 3600,
                "max-reclaim-leases": 100,
                "max-reclaim-time": 250,
                "flush-reclaimed-timer-wait-time": 25,
            },
            "authoritative": True,
            "valid-lifetime": 3600,
            "renew-timer": 900,
            "rebind-timer": 1800,
            "ddns-send-updates": False,
            "hooks-libraries": hooks,
            "subnet4": subnets,
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output_options": [{"output": "syslog:local0", "pattern": "%-5p %m\n"}],
                    "severity": "INFO",
                }
            ],
        }
    }
    header = (
        "// 이 파일은 Mooker Gateway Router Plane이 생성한다. 직접 수정하지 마라.\n"
        f"// tenant={policy.tenant} site={policy.site} revision={policy.revision}\n"
    )
    content = header + json.dumps(document, indent=2, ensure_ascii=False) + "\n"

    notes = []
    if not ctx.kea_hooks_library:
        notes.append(
            "libdhcp_lease_cmds.so를 찾지 못해 lease 조회 hook 없이 생성했다. "
            "`apt install kea-dhcp4-server` 후 재적용하면 control socket으로 lease 조회가 가능해진다.")
    if any(segment.dhcp and not segment.dhcp.unknown_clients_allowed for segment in segments):
        notes.append(
            "미등록 단말에 주소를 주지 않는 segment가 있다. 발견/승인 절차가 없으면 "
            "정상 단말도 네트워크에 붙지 못하므로 quarantine VLAN을 함께 운영해야 한다.")

    return RenderPlan(
        files=[FileTarget(KEA_DHCP4_FILE, content, 0o640, "Kea DHCPv4 설정")],
        precheck=[
            Command(("kea-dhcp4", "-t", KEA_DHCP4_FILE),
                    description="Kea 설정 문법/스키마 검증", stage_root_placeholder="@STAGE_FILE@",
                    timeout=30.0),
        ],
        services=[ServiceAction(UNIT_KEA4, "restart", description="DHCP 서버 반영")],
        managed_paths=[KEA_DHCP4_FILE],
        notes=notes,
        required_binaries=["kea-dhcp4"],
    )
