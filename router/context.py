"""렌더 컨텍스트: 렌더러가 알아야 하는 '환경 사실'을 한 번만 수집한다.

렌더러는 순수 함수를 유지해야 테스트와 diff가 안정적이다. 그래서 시스템을
들여다봐야 하는 값(설치된 Kea hook 경로, sch_cake 가용성, 기존 chap-secrets
내용 등)은 여기서 미리 모아 인자로 전달한다.
"""
from __future__ import annotations

import glob
from dataclasses import dataclass, field
from pathlib import Path

from .paths import PPP_SECRETS_FILE, SECRET_DIR
from .util import CommandRunner, read_text_or_none

KEA_HOOK_GLOBS = (
    "/usr/lib/*/kea/hooks/libdhcp_lease_cmds.so",
    "/usr/lib/kea/hooks/libdhcp_lease_cmds.so",
)


@dataclass
class RenderContext:
    secret_dir: str = SECRET_DIR
    kea_hooks_library: str | None = None
    existing_chap_secrets: str | None = None
    have_cake: bool = True
    have_bridge_nft: bool = True
    unbound_supports_rpz: bool = True
    detected: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def discover(runner: CommandRunner, secret_dir: str = SECRET_DIR) -> "RenderContext":
        hooks: str | None = None
        for pattern in KEA_HOOK_GLOBS:
            matches = sorted(glob.glob(pattern))
            if matches:
                hooks = matches[0]
                break
        cake = runner.run(["modinfo", "sch_cake"], timeout=10.0).ok or Path(
            "/sys/module/sch_cake").exists()
        bridge_nft = runner.run(["modprobe", "-n", "nf_tables_bridge"], timeout=10.0).ok
        version = runner.run(["unbound", "-V"], timeout=10.0)
        rpz = True
        if version.ok:
            first = version.stdout.splitlines()[0] if version.stdout else ""
            rpz = _version_at_least(first, (1, 17))
        return RenderContext(
            secret_dir=secret_dir,
            kea_hooks_library=hooks,
            existing_chap_secrets=read_text_or_none(PPP_SECRETS_FILE),
            have_cake=bool(cake),
            have_bridge_nft=bool(bridge_nft),
            unbound_supports_rpz=rpz,
            detected={"kea_hooks": hooks or "없음", "unbound": (version.stdout or "").strip()[:80]},
        )


def _version_at_least(text: str, minimum: tuple[int, int]) -> bool:
    digits: list[int] = []
    current = ""
    for char in text:
        if char.isdigit():
            current += char
        elif current:
            digits.append(int(current))
            current = ""
            if len(digits) >= 2:
                break
    if current and len(digits) < 2:
        digits.append(int(current))
    if len(digits) < 2:
        return True  # 판단 불가 시 기능을 막지 않는다(사전검사가 최종 판정한다)
    return (digits[0], digits[1]) >= minimum
