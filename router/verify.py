"""적용 후 연결 검증.

"명령이 성공했다"와 "네트워크가 살아 있다"는 다른 문제다. netplan apply가 0을
반환하고도 회선이 죽고, nft가 성공하고도 관리 경로가 막힐 수 있다. 그래서 적용
직후 실제 통신을 확인한다.

검사는 정책의 verify 블록이 요구하는 것만 hard로 취급한다. hard 검사가 하나라도
실패하면 controller가 즉시 스냅샷으로 되돌린다.

의존성을 줄이기 위해 DNS 질의는 표준 라이브러리 소켓으로 직접 만든다(dig/nslookup
설치를 전제하지 않는다).
"""
from __future__ import annotations

import ipaddress
import json
import random
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .model import Probe, RouterPolicy
from .util import LOG, CommandRunner


@dataclass
class NetworkProbes:
    """검증에 쓰는 네트워크 동작의 주입 지점.

    DNS 질의와 HTTPS 요청은 러너(subprocess)를 거치지 않으므로, 이 자리를 두지
    않으면 검증 로직 자체를 테스트할 수 없다. 기본값은 실제 구현이다.
    """

    dns_query: "Callable[[str, str, float], tuple[bool, str]]" = None  # type: ignore[assignment]
    https_get: "Callable[[str, float], tuple[bool, str]]" = None  # type: ignore[assignment]
    tcp_connect: "Callable[[str, int, float], tuple[bool, str]]" = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.dns_query is None:
            self.dns_query = _dns_query
        if self.https_get is None:
            self.https_get = _https_get
        if self.tcp_connect is None:
            self.tcp_connect = _tcp_connect


@dataclass
class VerifyCheck:
    name: str
    ok: bool
    detail: str = ""
    severity: str = "hard"
    duration_ms: int = 0

    def line(self) -> str:
        status = "OK" if self.ok else ("WARN" if self.severity == "soft" else "FAIL")
        return f"[{status:4}] {self.name}" + (f" — {self.detail}" if self.detail else "")


@dataclass
class VerifyReport:
    checks: list[VerifyCheck] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks if check.severity == "hard")

    def failures(self) -> list[VerifyCheck]:
        return [check for check in self.checks if check.severity == "hard" and not check.ok]

    def render(self) -> str:
        return "\n".join(check.line() for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [asdict(check) for check in self.checks]}


# ---------------------------------------------------------------------------
# 저수준 프로브
# ---------------------------------------------------------------------------
def _dns_query(server: str, name: str, timeout: float, port: int = 53) -> tuple[bool, str]:
    """A 레코드 질의를 직접 만들어 보낸다. 반환: (성공, 상세)."""
    transaction_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(label)]) + label.encode("idna") for label in name.rstrip(".").split(".")
    ) + b"\x00" + struct.pack(">HH", 1, 1)
    packet = header + question
    family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, port))
            data, _ = sock.recvfrom(2048)
    except (OSError, socket.timeout) as exc:
        return False, f"{server}: {exc}"
    if len(data) < 12:
        return False, f"{server}: 응답이 너무 짧다"
    resp_id, flags, _, answers = struct.unpack(">HHHH", data[:8])
    if resp_id != transaction_id:
        return False, f"{server}: transaction id 불일치"
    rcode = flags & 0x000F
    if rcode != 0:
        return False, f"{server}: rcode={rcode}"
    if answers == 0:
        return False, f"{server}: answer 0개"
    return True, f"{server}: answer {answers}개"


def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{host}:{port} 연결됨"
    except OSError as exc:
        return False, f"{host}:{port} {exc}"


def _https_get(url: str, timeout: float) -> tuple[bool, str]:
    context = ssl.create_default_context()
    request = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": "mooker-router-verify/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            code = response.status
            return code < 500, f"HTTP {code}"
    except urllib.error.HTTPError as exc:
        # 4xx는 '도달했다'는 뜻이므로 연결 검증 목적에서는 성공이다.
        return exc.code < 500, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, str(exc)


def _ping(runner: CommandRunner, target: str, timeout: float, device: str | None = None) -> tuple[bool, str]:
    argv = ["ping", "-c", "2", "-n", "-W", str(max(1, int(timeout)))]
    if device:
        argv.extend(["-I", device])
    argv.append(target)
    result = runner.run(argv, timeout=timeout * 3 + 5)
    return result.ok, result.summary(160)


def _run_probe(probe: Probe, runner: CommandRunner, device: str | None,
               probes: "NetworkProbes") -> tuple[bool, str]:
    if probe.kind == "icmp":
        return _ping(runner, probe.target, probe.timeout_s, device)
    if probe.kind == "tcp":
        return probes.tcp_connect(probe.target, probe.port or 443, probe.timeout_s)
    if probe.kind == "dns":
        return probes.dns_query(probe.target, probe.hostname or "www.example.com",
                                probe.timeout_s)
    if probe.kind == "https":
        return probes.https_get(f"https://{probe.hostname}/", probe.timeout_s)
    return False, f"알 수 없는 probe 종류: {probe.kind}"


# ---------------------------------------------------------------------------
# 검사 항목
# ---------------------------------------------------------------------------
def _ip_json(runner: CommandRunner, argv: list[str]) -> Any:
    result = runner.run(argv, timeout=15.0)
    if not result.ok:
        return None
    try:
        return json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return None


def _check_interfaces(policy: RouterPolicy, runner: CommandRunner, report: VerifyReport) -> None:
    addresses = _ip_json(runner, ["ip", "-json", "addr", "show"])
    if addresses is None:
        report.checks.append(VerifyCheck("interface:조회", False, "ip -json addr 실패", "hard"))
        return
    by_name = {entry.get("ifname"): entry for entry in addresses if isinstance(entry, dict)}

    for segment in policy.lans:
        entry = by_name.get(segment.interface)
        if entry is None:
            report.checks.append(VerifyCheck(
                f"interface:{segment.interface}", False, "인터페이스가 없다", "hard"))
            continue
        live = {
            f"{info.get('local')}/{info.get('prefixlen')}"
            for info in entry.get("addr_info", []) if info.get("local")
        }
        expected = {str(ipaddress.ip_interface(cidr)) for cidr in segment.addresses}
        missing = expected - live
        operstate = entry.get("operstate", "?")
        report.checks.append(VerifyCheck(
            f"interface:{segment.interface}",
            not missing and operstate in {"UP", "UNKNOWN"},
            f"operstate={operstate}" + (f" 누락 주소={sorted(missing)}" if missing else ""),
            "hard",
        ))

    for link in policy.wan_links:
        entry = by_name.get(link.link_interface)
        if entry is None:
            report.checks.append(VerifyCheck(
                f"wan:{link.name}:link", False, f"{link.link_interface} 없음",
                "hard" if link.required_for_online else "soft"))
            continue
        has_address = any(info.get("local") for info in entry.get("addr_info", []))
        report.checks.append(VerifyCheck(
            f"wan:{link.name}:address", has_address,
            f"operstate={entry.get('operstate')}" + ("" if has_address else " 주소 없음"),
            "hard" if link.required_for_online else "soft",
        ))


def _check_routes(policy: RouterPolicy, runner: CommandRunner, report: VerifyReport) -> None:
    routes = _ip_json(runner, ["ip", "-json", "route", "show", "default"])
    if routes is None:
        report.checks.append(VerifyCheck("route:default", False, "ip -json route 실패", "hard"))
        return
    devices = {route.get("dev") for route in routes if isinstance(route, dict)}
    report.checks.append(VerifyCheck(
        "route:default", bool(devices), f"기본 경로 장치={sorted(d for d in devices if d)}",
        "hard" if policy.verify.require_wan_online else "soft"))
    for link in policy.wan_links:
        if not link.required_for_online:
            continue
        report.checks.append(VerifyCheck(
            f"route:{link.name}", link.link_interface in devices,
            f"{link.link_interface} 기본 경로 " + ("존재" if link.link_interface in devices else "없음"),
            "soft",  # 다회선 failover 중이면 한쪽이 없을 수 있다
        ))


def _check_wan_probes(policy: RouterPolicy, runner: CommandRunner, report: VerifyReport,
                      probes: "NetworkProbes") -> None:
    required = policy.verify.require_wan_online
    online_any = False
    for link in policy.wan_links:
        if not link.probes:
            continue
        results = [_run_probe(probe, runner, link.link_interface, probes)
                   for probe in link.probes]
        ok = any(result for result, _ in results)
        online_any = online_any or ok
        detail = "; ".join(text for _, text in results)[:300]
        report.checks.append(VerifyCheck(
            f"wan:{link.name}:probe", ok, detail,
            "hard" if (required and link.required_for_online) else "soft"))
    if required and any(link.probes for link in policy.wan_links):
        report.checks.append(VerifyCheck(
            "wan:최소 1회선 온라인", online_any,
            "" if online_any else "모든 WAN probe 실패", "hard"))


def _check_dns(policy: RouterPolicy, report: VerifyReport, probes: "NetworkProbes") -> None:
    if not policy.dns.enabled:
        return
    severity = "hard" if policy.verify.require_dns else "soft"
    targets = ["127.0.0.1"]
    for segment in policy.dns_listen_segments:
        gateway = segment.gateway_ipv4
        if gateway:
            targets.append(gateway)
    results = []
    for server in dict.fromkeys(targets):
        started = time.monotonic()
        ok, detail = probes.dns_query(server, policy.verify.dns_probe_name,
                                      policy.verify.per_check_timeout_s)
        results.append((server, ok, detail, int((time.monotonic() - started) * 1000)))
    any_ok = any(ok for _, ok, _, _ in results)
    report.checks.append(VerifyCheck(
        "dns:로컬 resolver", any_ok,
        "; ".join(f"{s}({'ok' if ok else d})" for s, ok, d, _ in results)[:300],
        severity, max((ms for _, _, _, ms in results), default=0)))

    # 차단 정책이 실제로 동작하는지도 확인한다(설정만 반영되고 효력이 없는 경우가 있다).
    if policy.dns.blocked_domains:
        blocked = policy.dns.blocked_domains[0]
        ok, detail = probes.dns_query("127.0.0.1", blocked,
                                      policy.verify.per_check_timeout_s)
        report.checks.append(VerifyCheck(
            "dns:차단 정책 효력", not ok,
            f"{blocked} 응답={'있음(차단 미적용)' if ok else '없음(정상)'} {detail}", "soft"))


def _check_control_plane(policy: RouterPolicy, report: VerifyReport,
                         probes: "NetworkProbes") -> None:
    if not policy.verify.control_plane_url:
        return
    started = time.monotonic()
    ok, detail = probes.https_get(policy.verify.control_plane_url,
                                  policy.verify.per_check_timeout_s)
    report.checks.append(VerifyCheck(
        "control-plane:도달", ok, f"{policy.verify.control_plane_url} {detail}",
        "hard" if policy.verify.require_control_plane else "soft",
        int((time.monotonic() - started) * 1000)))


def _check_mgmt_tunnel(policy: RouterPolicy, runner: CommandRunner, report: VerifyReport) -> None:
    tunnel = policy.mgmt_tunnel
    if not tunnel.enabled:
        return
    severity = "hard" if policy.verify.require_mgmt_tunnel else "soft"
    result = runner.run(["wg", "show", tunnel.interface, "latest-handshakes"], timeout=15.0)
    if not result.ok:
        report.checks.append(VerifyCheck("mgmt-tunnel:상태", False,
                                         result.summary(160) or "wg show 실패", severity))
        return
    newest = 0
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            newest = max(newest, int(parts[1]))
    if newest == 0:
        report.checks.append(VerifyCheck("mgmt-tunnel:handshake", False,
                                         "핸드셰이크 기록 없음", severity))
        return
    age = int(time.time()) - newest
    report.checks.append(VerifyCheck(
        "mgmt-tunnel:handshake", age <= 180, f"{age}초 전", severity))


def _check_services(policy: RouterPolicy, runner: CommandRunner, report: VerifyReport) -> None:
    from .paths import UNIT_KEA4, UNIT_NETWORKD, UNIT_UNBOUND

    units = [UNIT_NETWORKD]
    if policy.dhcp_segments:
        units.append(UNIT_KEA4)
    if policy.dns.enabled:
        units.append(UNIT_UNBOUND)
    for unit in units:
        result = runner.run(["systemctl", "is-active", unit], timeout=15.0)
        state = (result.stdout or "").strip() or "unknown"
        report.checks.append(VerifyCheck(f"service:{unit}", state == "active", state, "hard"))


def _check_nftables(runner: CommandRunner, report: VerifyReport) -> None:
    result = runner.run(["nft", "list", "table", "inet", "mooker"], timeout=15.0)
    if not result.ok:
        report.checks.append(VerifyCheck("nftables:inet mooker", False,
                                         result.summary(160) or "테이블 없음", "hard"))
        return
    text = result.stdout
    required_chains = ("chain input", "chain forward", "chain srcnat")
    missing = [chain for chain in required_chains if chain not in text]
    report.checks.append(VerifyCheck(
        "nftables:inet mooker", not missing,
        f"누락 체인={missing}" if missing else f"{len(text.splitlines())} 줄 적용됨", "hard"))


def verify(policy: RouterPolicy, runner: CommandRunner, *, skip_delay: bool = False,
           probes: "NetworkProbes | None" = None) -> VerifyReport:
    """정책이 요구하는 검증을 모두 수행한다."""
    probes = probes or NetworkProbes()
    report = VerifyReport()
    if not skip_delay and policy.verify.settle_delay_s:
        # DHCP 재획득, RA, 링크 협상에 시간이 필요하다. 여기서 성급하게 판정하면
        # 정상 적용을 실패로 오인해 불필요한 rollback을 유발한다.
        LOG.info("안정화 대기 %.1fs", policy.verify.settle_delay_s)
        time.sleep(policy.verify.settle_delay_s)

    _check_interfaces(policy, runner, report)
    _check_routes(policy, runner, report)
    _check_nftables(runner, report)
    _check_services(policy, runner, report)
    _check_wan_probes(policy, runner, report, probes)
    _check_dns(policy, report, probes)
    _check_mgmt_tunnel(policy, runner, report)
    _check_control_plane(policy, report, probes)

    LOG.info("검증 결과 ok=%s (실패 %d건)", report.ok, len(report.failures()))
    return report
