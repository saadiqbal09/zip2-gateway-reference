"""WireGuard 관리 터널 렌더러.

중앙 운영플랫폼으로의 관리 경로다. 세 가지를 지킨다.

- 개인키는 정책에 없다. ``/etc/mooker/secrets/<private_key_ref>``에서 읽어
  설정 파일(0600)에만 기록한다.
- ``AllowedIPs``는 최소 권한이다. 정책 검증 단계에서 0.0.0.0/0을 거부한다.
- 적용은 ``wg syncconf``로 한다. 인터페이스를 내리지 않으므로 이미 붙어 있는
  관리 세션이 끊기지 않는다(원격 작업 중 자기 발등 찍는 사고 방지).
"""
from __future__ import annotations

from pathlib import Path

from ..context import RenderContext
from ..errors import RenderError
from ..model import RouterPolicy
from ..paths import RUN_DIR, WG_DIR
from ..plan import Command, FileTarget, RenderPlan, managed


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    tunnel = policy.mgmt_tunnel
    if not tunnel.enabled:
        return RenderPlan(notes=["관리 터널 비활성"])

    key_path = Path(ctx.secret_dir) / tunnel.private_key_ref
    try:
        private_key = key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RenderError(
            f"WireGuard 개인키를 읽을 수 없다: {key_path} ({exc}). "
            f"`wg genkey > {key_path} && chmod 600 {key_path}` 후 재시도한다.") from exc
    if len(private_key) != 44 or not private_key.endswith("="):
        raise RenderError(f"WireGuard 개인키 형식이 아니다: {key_path}")

    config_path = f"{WG_DIR}/{tunnel.interface}.conf"
    lines = [
        f"# 관리 터널 {tunnel.interface} (revision={policy.revision})",
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {tunnel.address}",
        f"MTU = {tunnel.mtu}",
    ]
    if tunnel.listen_port:
        lines.append(f"ListenPort = {tunnel.listen_port}")
    if tunnel.table:
        lines.append(f"Table = {tunnel.table}")
    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {tunnel.peer_public_key}",
        f"Endpoint = {tunnel.peer_endpoint}",
        f"AllowedIPs = {', '.join(tunnel.allowed_ips)}",
    ])
    if tunnel.keepalive_s:
        lines.append(f"PersistentKeepalive = {tunnel.keepalive_s}")

    stripped_path = f"{RUN_DIR}/{tunnel.interface}.stripped.conf"

    return RenderPlan(
        files=[FileTarget(config_path, managed("\n".join(lines) + "\n"), 0o600,
                          f"WireGuard 관리 터널 {tunnel.interface}")],
        precheck=[
            Command(("wg-quick", "strip", config_path),
                    description="WireGuard 설정 파싱 검증", stage_root_placeholder="@STAGE_FILE@",
                    timeout=15.0),
        ],
        apply_commands=[
            # 인터페이스가 없으면 올리고, 있으면 무중단으로 설정만 갱신한다.
            Command(("sh", "-c",
                     f'if ip link show {tunnel.interface} >/dev/null 2>&1; then '
                     f'umask 077; wg-quick strip {config_path} > {stripped_path} && '
                     f'wg syncconf {tunnel.interface} {stripped_path} && rm -f {stripped_path}; '
                     f'else wg-quick up {config_path}; fi'),
                    description="관리 터널 무중단 갱신 또는 기동", timeout=30.0),
        ],
        managed_paths=[config_path],
        notes=[
            "관리 터널은 Gateway가 outbound로 개시한다. WAN에 인바운드 포트를 열지 않는다.",
            "키 회전은 중앙에서 새 secret을 배치한 뒤 정책 revision을 올려 syncconf로 반영한다.",
        ],
        required_binaries=["wg", "wg-quick"],
    )
