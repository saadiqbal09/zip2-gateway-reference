"""PPPoE WAN 렌더러.

netplan/systemd-networkd는 PPPoE를 다루지 않는다. Ubuntu에서는 pppd(rp-pppoe
플러그인)를 쓰는 것이 표준이므로, peers 파일과 인스턴스 유닛을 생성한다.

비밀번호는 정책에 담기지 않는다. ``/etc/mooker/secrets/<password_ref>`` 파일에서
읽어 chap-secrets의 Mooker 관리 블록에만 기록한다(파일 권한 0600).
"""
from __future__ import annotations

from pathlib import Path

from ..errors import RenderError
from ..context import RenderContext
from ..model import RouterPolicy, WanLink
from ..paths import PPP_PEERS_DIR, PPP_SECRETS_FILE
from ..plan import Command, FileTarget, RenderPlan, ServiceAction, managed

BLOCK_START = "# >>> mooker-router managed >>>"
BLOCK_END = "# <<< mooker-router managed <<<"


def _read_secret(ref: str, secret_dir: str) -> str:
    path = Path(secret_dir) / ref
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RenderError(
            f"PPPoE 비밀값을 읽을 수 없다: {path} ({exc}). "
            f"정책 적용 전에 secret을 배치해야 한다.") from exc
    if not value:
        raise RenderError(f"PPPoE 비밀값이 비어 있다: {path}")
    if "\n" in value or " " in value:
        raise RenderError(f"PPPoE 비밀값에 공백/개행이 있다: {path}")
    return value


def _peer_file(link: WanLink) -> str:
    spec = link.pppoe
    assert spec is not None
    lines = [
        f"# WAN {link.name} (PPPoE) — 물리 인터페이스 {link.interface}",
        f"plugin rp-pppoe.so {link.interface}",
        f"user \"{spec.username}\"",
        f"ifname ppp-{link.name}",
        "noipdefault",
        "defaultroute",
        f"defaultroute-metric {link.metric}",
        "replacedefaultroute" if link.metric <= 100 else "# 보조 회선: 기본 경로를 대체하지 않는다",
        "persist",
        "maxfail 0",
        "holdoff 5",
        f"mtu {spec.mtu}",
        f"mru {spec.mtu}",
        "noauth",
        "hide-password",
        # ISP DNS를 시스템에 밀어넣지 않는다. 로컬 Unbound가 유일한 resolver다.
        "usepeerdns" if not link.nameservers else "# usepeerdns 비활성: 정책 nameservers 사용",
        f"lcp-echo-interval {spec.lcp_echo_interval}",
        f"lcp-echo-failure {spec.lcp_echo_failure}",
    ]
    if spec.service:
        lines.append(f"rp_pppoe_service {spec.service}")
    if spec.access_concentrator:
        lines.append(f"rp_pppoe_ac {spec.access_concentrator}")
    return managed("\n".join(lines) + "\n")


def _chap_secrets(policy: RouterPolicy, secret_dir: str, existing: str | None) -> str:
    """기존 chap-secrets를 보존하고 Mooker 관리 블록만 교체한다."""
    entries = [BLOCK_START]
    for link in policy.wan_links:
        if link.mode != "pppoe" or link.pppoe is None:
            continue
        password = _read_secret(link.pppoe.password_ref, secret_dir)
        entries.append(f'"{link.pppoe.username}" * "{password}" *')
    entries.append(BLOCK_END)
    block = "\n".join(entries)

    base = existing if existing is not None else "# client\tserver\tsecret\tIP addresses\n"
    if BLOCK_START in base and BLOCK_END in base:
        head = base.split(BLOCK_START)[0]
        tail = base.split(BLOCK_END)[1]
        return head + block + tail
    if not base.endswith("\n"):
        base += "\n"
    return base + block + "\n"


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    secret_dir = ctx.secret_dir
    existing_chap_secrets = ctx.existing_chap_secrets
    pppoe_links = [link for link in policy.wan_links if link.mode == "pppoe"]
    if not pppoe_links:
        return RenderPlan()

    files: list[FileTarget] = []
    services: list[ServiceAction] = []
    apply_commands: list[Command] = []
    precheck: list[Command] = []

    for link in pppoe_links:
        peer_path = f"{PPP_PEERS_DIR}/mooker-{link.name}"
        files.append(FileTarget(peer_path, _peer_file(link), 0o600, f"PPPoE peer {link.name}"))
        unit = f"mooker-pppoe@{link.name}.service"
        services.append(ServiceAction(unit, "restart", description=f"PPPoE 세션 {link.name}"))
        precheck.append(
            Command(("pppd", "dryrun", "call", f"mooker-{link.name}"),
                    description=f"pppd 옵션 검증 ({link.name})", allow_fail=True, timeout=15.0))

    existing = existing_chap_secrets
    if existing is None:
        try:
            existing = Path(PPP_SECRETS_FILE).read_text(encoding="utf-8")
        except OSError:
            existing = None
    files.append(FileTarget(PPP_SECRETS_FILE, _chap_secrets(policy, secret_dir, existing), 0o600,
                            "PPPoE 인증정보 (Mooker 관리 블록)"))

    apply_commands.append(
        Command(("systemctl", "daemon-reload"), description="PPPoE 유닛 재로드", timeout=30.0))

    return RenderPlan(
        files=files,
        precheck=precheck,
        apply_commands=apply_commands,
        services=services,
        managed_paths=[PPP_SECRETS_FILE],
        notes=[
            "PPPoE는 pppd로 동작한다. mooker-pppoe@<wan>.service 유닛이 설치되어 있어야 한다"
            " (install.sh가 배치한다).",
        ],
        required_binaries=["pppd"],
    )
