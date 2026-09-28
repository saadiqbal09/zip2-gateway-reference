"""사전검사: 시스템을 건드리지 않고 '이 계획이 실제로 적용 가능한가'를 확인한다.

핵심은 staging 루트다. 렌더된 파일을 임시 디렉터리 아래 같은 상대 경로로 쓰고,
각 도구의 검증 모드를 그 경로에 대해 실행한다.

    netplan generate --root-dir <staging>     : 실제 /run 을 건드리지 않는다
    nft -c -f <staging>/etc/.../mooker.nft    : 커널에 커밋하지 않는다
    kea-dhcp4 -t <staging>/etc/kea/...        : 설정만 파싱한다
    unbound-checkconf <staging>/etc/...       : 설정만 파싱한다
    wg-quick strip <staging>/etc/wireguard/...: 설정만 파싱한다

여기서 실패하면 아무것도 바뀌지 않은 상태로 끝난다. 이 성질이 원격 정책 배포의
안전성을 만든다.
"""
from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import PrecheckError
from .plan import Command, RenderPlan
from .util import LOG, CommandRunner, atomic_write, staged_path


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ""
    severity: str = "hard"  # hard | soft
    skipped: bool = False

    def line(self) -> str:
        status = "SKIP" if self.skipped else ("OK" if self.ok else
                                             ("WARN" if self.severity == "soft" else "FAIL"))
        return f"[{status:4}] {self.name}" + (f" — {self.detail}" if self.detail else "")


@dataclass
class PrecheckReport:
    checks: list[CheckResult] = field(default_factory=list)
    staging_root: str = ""

    @property
    def ok(self) -> bool:
        return not any(check.severity == "hard" and not check.ok and not check.skipped
                       for check in self.checks)

    def failures(self) -> list[CheckResult]:
        return [check for check in self.checks
                if check.severity == "hard" and not check.ok and not check.skipped]

    def render(self) -> str:
        return "\n".join(check.line() for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [
                {"name": c.name, "ok": c.ok, "detail": c.detail, "severity": c.severity,
                 "skipped": c.skipped}
                for c in self.checks
            ],
        }


class StagingArea:
    """렌더 결과를 임시 루트에 배치한다."""

    def __init__(self, plan: RenderPlan):
        self.plan = plan
        self.root = Path(tempfile.mkdtemp(prefix="mooker-precheck-"))

    def __enter__(self) -> "StagingArea":
        for target in self.plan.files:
            atomic_write(target.path, target.rendered(), target.mode, root=self.root)
        return self

    def __exit__(self, *exc_info) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def resolve(self, command: Command) -> list[str]:
        """명령 인자에서 staging 경로 치환을 수행한다."""
        argv: list[str] = []
        managed = {target.path for target in self.plan.files}
        for arg in command.argv:
            if command.stage_root_placeholder and arg == command.stage_root_placeholder:
                argv.append(str(self.root))
            elif arg in managed:
                argv.append(str(staged_path(arg, self.root)))
            elif command.stage_root_placeholder == "@STAGE@" and arg.startswith("@STAGE@"):
                argv.append(arg.replace("@STAGE@", str(self.root)))
            else:
                argv.append(arg)
        return argv


def run(plan: RenderPlan, runner: CommandRunner, *, strict_binaries: bool = True,
        file_root: str | None = None) -> PrecheckReport:
    report = PrecheckReport()

    # 1) 필요한 바이너리가 있는지. 없으면 적용 중간에 실패한다.
    for binary in plan.required_binaries:
        found = runner.which(binary)
        report.checks.append(CheckResult(
            name=f"binary:{binary}",
            ok=bool(found),
            detail=found or "설치되지 않았다 (apt로 설치 후 재시도)",
            severity="hard" if strict_binaries else "soft",
        ))

    # 2) 파일 경로의 상위 디렉터리가 쓰기 가능한지 (권한 문제를 미리 잡는다)
    import os

    for directory in sorted({str(Path(target.path).parent) for target in plan.files}):
        # 아직 없는 디렉터리는 우리가 만들 것이므로, 만들 수 있는지를 본다.
        # 가장 가까운 상위 디렉터리의 쓰기 권한이 실질적인 판정 기준이다.
        probe = Path(staged_path(directory, file_root))
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        writable = os.access(probe, os.W_OK)
        target = Path(staged_path(directory, file_root))
        note = "" if probe == target else f"(상위 {probe} 기준)"
        report.checks.append(CheckResult(
            name=f"dir:{directory}",
            ok=writable,
            detail=note if writable else f"쓰기 권한이 없다 {note} (root로 실행하는지 확인)".strip(),
            severity="hard",
        ))

    # 3) 도구별 설정 검증 (staging)
    with StagingArea(plan) as staging:
        report.staging_root = str(staging.root)
        for command in plan.precheck:
            binary = command.argv[0]
            if not runner.which(binary):
                report.checks.append(CheckResult(
                    name=command.description or command.display(),
                    ok=False, skipped=True,
                    detail=f"{binary}가 없어 건너뛴다",
                    severity="hard" if command.argv[0] in {"nft", "netplan"} else "soft",
                ))
                continue
            argv = staging.resolve(command)
            result = runner.run(argv, timeout=command.timeout)
            report.checks.append(CheckResult(
                name=command.description or command.display(),
                ok=result.ok,
                detail=result.summary() if not result.ok else "",
                severity="soft" if command.allow_fail else "hard",
            ))
            LOG.debug("precheck %s -> rc=%s", " ".join(argv), result.returncode)

    return report


def run_or_raise(plan: RenderPlan, runner: CommandRunner,
                 file_root: str | None = None) -> PrecheckReport:
    report = run(plan, runner, file_root=file_root)
    if not report.ok:
        detail = "; ".join(check.line() for check in report.failures())
        raise PrecheckError(f"사전검사 실패 — 시스템은 변경되지 않았다: {detail}", report=report)
    return report
