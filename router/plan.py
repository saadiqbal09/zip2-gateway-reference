"""RenderPlan: 적용 대상의 완전한 명세.

정책을 컴파일한 결과는 '설정 파일 집합 + 사전검사 명령 + 적용 명령 + 서비스
액션'이다. 이 객체가 있으면 적용 없이도 diff와 검사가 가능하고, 감사 로그에
"무엇을 바꿀 것인가"를 정확히 남길 수 있다.
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path

from .util import read_text_or_none

MANAGED_HEADER = (
    "# 이 파일은 Mooker Gateway Router Plane이 생성한다. 직접 수정하지 마라.\n"
    "# 수동 변경은 다음 정책 적용 시 되돌려진다.\n"
)


@dataclass(frozen=True)
class FileTarget:
    path: str
    content: str
    mode: int = 0o640
    description: str = ""
    # 적용 후에도 관리 대상으로 유지되는지. False면 /run 아래 임시 산출물.
    persistent: bool = True

    def rendered(self) -> str:
        return self.content if self.content.endswith("\n") else self.content + "\n"


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    stdin: str | None = None
    timeout: float = 30.0
    description: str = ""
    allow_fail: bool = False
    # 사전검사 단계에서 staging 루트를 인자로 치환해야 하는 경우 사용
    stage_root_placeholder: str | None = None

    def display(self) -> str:
        return " ".join(self.argv)


@dataclass(frozen=True)
class ServiceAction:
    unit: str
    action: str  # restart | reload | reload-or-restart | start | stop | enable | disable
    ignore_missing: bool = True
    description: str = ""


@dataclass
class RenderPlan:
    """렌더러 산출물. 여러 렌더러의 결과를 merge해 하나의 적용 계획을 만든다."""

    files: list[FileTarget] = field(default_factory=list)
    precheck: list[Command] = field(default_factory=list)
    apply_commands: list[Command] = field(default_factory=list)
    services: list[ServiceAction] = field(default_factory=list)
    # 스냅샷/복구가 관리해야 하는 경로 (렌더 결과에 없더라도 이전 상태 보존 대상)
    managed_paths: list[str] = field(default_factory=list)
    # 우리가 소유하는 파일 패턴. 이번 계획에 없는데 이 패턴에 걸리는 파일은
    # 이전 정책이 남긴 잔여물이므로 제거 대상이다. 디렉터리 목록이 아니라
    # 패턴이어야 한다 — VLAN을 정책에서 지우면 그 디렉터리 자체가 계획에서
    # 사라지므로, 디렉터리 기준으로는 잔여 파일을 영원히 찾지 못한다.
    owned_globs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    required_binaries: list[str] = field(default_factory=list)

    def merge(self, other: "RenderPlan") -> "RenderPlan":
        self.files.extend(other.files)
        self.precheck.extend(other.precheck)
        self.apply_commands.extend(other.apply_commands)
        self.services.extend(other.services)
        self.managed_paths.extend(other.managed_paths)
        self.owned_globs.extend(other.owned_globs)
        self.notes.extend(other.notes)
        self.required_binaries.extend(other.required_binaries)
        return self

    def finalize(self) -> "RenderPlan":
        """중복 제거 및 경로 충돌 검사."""
        seen: dict[str, FileTarget] = {}
        for target in self.files:
            if target.path in seen and seen[target.path].content != target.content:
                raise ValueError(f"두 렌더러가 같은 경로를 서로 다르게 생성한다: {target.path}")
            seen[target.path] = target
        self.files = list(seen.values())
        self.managed_paths = sorted({*self.managed_paths, *(t.path for t in self.files if t.persistent)})
        self.owned_globs = sorted(set(self.owned_globs))
        self.required_binaries = sorted(set(self.required_binaries))
        return self

    # --- 조회 -------------------------------------------------------------
    def file_paths(self) -> list[str]:
        return [target.path for target in self.files]

    def persistent_files(self) -> list[FileTarget]:
        return [target for target in self.files if target.persistent]

    def diff(self, root: str | Path | None = None) -> str:
        """현재 디스크 내용과의 통합 diff. ``mooker-router plan``의 출력."""
        chunks: list[str] = []
        for target in sorted(self.files, key=lambda t: t.path):
            live_path = Path(root) / target.path.lstrip("/") if root else Path(target.path)
            current = read_text_or_none(live_path)
            new = target.rendered()
            if current == new:
                continue
            diff = difflib.unified_diff(
                (current or "").splitlines(keepends=True),
                new.splitlines(keepends=True),
                fromfile=f"a{target.path}" + ("" if current is not None else " (없음)"),
                tofile=f"b{target.path}",
            )
            chunks.append("".join(diff))
        return "\n".join(chunks)

    def changed_files(self, root: str | Path | None = None) -> list[str]:
        changed = []
        for target in self.files:
            live_path = Path(root) / target.path.lstrip("/") if root else Path(target.path)
            if read_text_or_none(live_path) != target.rendered():
                changed.append(target.path)
        return sorted(changed)

    def describe(self) -> str:
        lines = ["[파일]"]
        for target in sorted(self.files, key=lambda t: t.path):
            lines.append(f"  {target.path}  mode={oct(target.mode)}  {target.description}")
        lines.append("[사전검사]")
        for command in self.precheck:
            lines.append(f"  {command.display()}   # {command.description}")
        lines.append("[적용 명령]")
        for command in self.apply_commands:
            lines.append(f"  {command.display()}   # {command.description}")
        lines.append("[서비스]")
        for service in self.services:
            lines.append(f"  systemctl {service.action} {service.unit}   # {service.description}")
        if self.notes:
            lines.append("[참고]")
            lines.extend(f"  - {note}" for note in self.notes)
        return "\n".join(lines)


def managed(content: str, comment: str = "#") -> str:
    """관리 대상 파일 머리말을 붙인다."""
    if comment == "#":
        return MANAGED_HEADER + content
    header = "\n".join(f"{comment} {line.lstrip('# ').rstrip()}" for line in MANAGED_HEADER.strip().splitlines())
    return header + "\n" + content
