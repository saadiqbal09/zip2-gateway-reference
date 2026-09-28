"""systemd-networkd 드롭인 렌더러.

netplan이 표현하지 못하는 L2 세부사항을 담당한다.

- VLAN-aware bridge (`VLANFiltering=yes`, `DefaultPVID`)
- 포트별 access(PVID/untagged) / trunk(tagged) VLAN 할당
- 포트 격리(`Isolated=yes`) — 같은 브리지 안에서 포트 간 직접 통신 차단

netplan은 자신의 설정을 ``/run/systemd/network/10-netplan-<이름>.{netdev,network}``
로 생성한다. systemd-networkd는 같은 이름의 드롭인 디렉터리
``/etc/systemd/network/<파일명>.d/*.conf``를 추가로 읽는다. 따라서 netplan 파일을
고쳐 쓰지 않고 필요한 섹션만 얹을 수 있다. 이것이 두 도구를 섞어 쓰는 가장 덜
위험한 방식이다.
"""
from __future__ import annotations

from collections import defaultdict

from ..context import RenderContext
from ..errors import RenderError
from ..model import RouterPolicy
from ..paths import NETWORKD_DIR, UNIT_NETWORKD
from ..plan import Command, FileTarget, RenderPlan, ServiceAction, managed

DROPIN_NAME = "50-mooker-l2.conf"


def _netdev_dropin(bridge) -> str:
    return managed(
        "\n".join(
            [
                f"# bridge {bridge.name}: VLAN filtering",
                "[Bridge]",
                f"VLANFiltering={'yes' if bridge.vlan_filtering else 'no'}",
                f"DefaultPVID={bridge.default_pvid}",
                f"STP={'yes' if bridge.stp else 'no'}",
                "",
            ]
        )
    )


def _bridge_self_network(bridge, vlan_ids: list[int]) -> str:
    lines = [f"# bridge {bridge.name} 자체 포트에 VLAN 등록 (VLAN 서브인터페이스 수신용)"]
    for vlan_id in sorted(set(vlan_ids)):
        lines.extend(["[BridgeVLAN]", f"VLAN={vlan_id}", ""])
    if not vlan_ids:
        lines.append("# 등록할 VLAN이 없다")
    return managed("\n".join(lines) + "\n")


def _port_network(bridge, port: str, pvid: int | None, tagged: list[int], isolated: bool) -> str:
    lines = [f"# bridge {bridge.name} port {port}"]
    if isolated:
        lines.extend(["[Bridge]", "Isolated=yes", ""])
    if pvid is not None:
        lines.extend(["[BridgeVLAN]", f"PVID={pvid}", f"EgressUntagged={pvid}", ""])
    for vlan_id in sorted(set(tagged)):
        if vlan_id == pvid:
            continue
        lines.extend(["[BridgeVLAN]", f"VLAN={vlan_id}", ""])
    if pvid is None and not tagged and not isolated:
        lines.append(f"# 기본 PVID({bridge.default_pvid}) 사용, 추가 설정 없음")
    return managed("\n".join(lines) + "\n")


def _validate_ini(content: str, path: str) -> None:
    """생성한 드롭인이 systemd가 읽을 수 있는 INI 구조인지 자체 검증한다."""
    section: str | None = None
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            if not section or not section.isalnum():
                raise RenderError(f"{path}:{number} 잘못된 섹션 이름: {stripped}")
            continue
        if section is None:
            raise RenderError(f"{path}:{number} 섹션 밖의 설정: {stripped}")
        if "=" not in stripped:
            raise RenderError(f"{path}:{number} key=value 형식이 아니다: {stripped}")
        key = stripped.split("=", 1)[0].strip()
        if not key or " " in key:
            raise RenderError(f"{path}:{number} 잘못된 키: {stripped}")


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    files: list[FileTarget] = []
    notes: list[str] = []

    # bridge별 VLAN 목록과 포트 할당 계산
    vlans_by_bridge: dict[str, list[int]] = defaultdict(list)
    pvid_by_port: dict[str, int] = {}
    for segment in policy.lans:
        if segment.vlan_id is None or not segment.vlan_link:
            continue
        vlans_by_bridge[segment.vlan_link].append(segment.vlan_id)
        for port in segment.untagged_ports:
            pvid_by_port[port] = segment.vlan_id

    for bridge in policy.bridges:
        if not bridge.vlan_filtering and not bridge.isolated_ports:
            continue
        netdev_dir = f"{NETWORKD_DIR}/10-netplan-{bridge.name}.netdev.d"
        network_dir = f"{NETWORKD_DIR}/10-netplan-{bridge.name}.network.d"
        if bridge.vlan_filtering:
            files.append(FileTarget(f"{netdev_dir}/{DROPIN_NAME}", _netdev_dropin(bridge), 0o644,
                                    f"bridge {bridge.name} VLAN filtering"))
            files.append(FileTarget(f"{network_dir}/{DROPIN_NAME}",
                                    _bridge_self_network(bridge, vlans_by_bridge.get(bridge.name, [])),
                                    0o644, f"bridge {bridge.name} self VLAN 등록"))
        trunk_vlans = sorted(set(vlans_by_bridge.get(bridge.name, [])))
        for port in bridge.ports:
            port_dir = f"{NETWORKD_DIR}/10-netplan-{port}.network.d"
            pvid = pvid_by_port.get(port)
            tagged = trunk_vlans if port in bridge.trunk_ports else []
            isolated = port in bridge.isolated_ports
            if pvid is None and not tagged and not isolated:
                continue
            files.append(FileTarget(f"{port_dir}/{DROPIN_NAME}",
                                    _port_network(bridge, port, pvid, tagged, isolated), 0o644,
                                    f"port {port} VLAN/격리"))
        if bridge.vlan_filtering and not bridge.trunk_ports and not any(
            port in pvid_by_port for port in bridge.ports
        ):
            notes.append(
                f"bridge '{bridge.name}'에 VLAN filtering을 켰지만 access/trunk 포트 할당이 없다. "
                f"모든 포트가 기본 PVID {bridge.default_pvid}로 동작한다.")

    for target in files:
        _validate_ini(target.content, target.path)

    if not files:
        return RenderPlan(notes=["L2 드롭인 없음 (VLAN filtering/격리 미사용)"])

    return RenderPlan(
        files=files,
        # systemd에는 .network/.netdev 드롭인 검증기가 없다(systemd-analyze verify는
        # 유닛 전용이다). 그래서 생성 직후 우리가 직접 INI 구조를 검증한다.
        precheck=[],
        apply_commands=[
            # netplan generate/apply 이후에 networkd를 다시 읽혀야 드롭인이 반영된다.
            Command(("networkctl", "reload"), description="networkd 설정 재적용", timeout=30.0),
        ],
        services=[ServiceAction(UNIT_NETWORKD, "reload-or-restart", description="networkd 반영")],
        # 어떤 인터페이스의 드롭인이든 이 패턴에 걸린다. 정책에서 사라진
        # 인터페이스의 잔여 파일까지 정리하기 위해 패턴으로 소유권을 선언한다.
        owned_globs=[
            f"{NETWORKD_DIR}/*.network.d/{DROPIN_NAME}",
            f"{NETWORKD_DIR}/*.netdev.d/{DROPIN_NAME}",
        ],
        notes=notes,
        required_binaries=["networkctl"],
    )
