"""적용 단계.

사전검사를 통과한 RenderPlan만 여기로 온다. 하는 일은 세 가지다.

1. 파일 쓰기 (원자적, 권한 지정, 우리 소유 디렉터리의 잔여 파일 정리)
2. 적용 명령 순차 실행 (allow_fail이 아닌 명령이 실패하면 즉시 중단)
3. systemd 서비스 액션

중단 시 예외를 던지지 않고 ApplyLog를 돌려준다. 호출자(controller)가 스냅샷
복구를 결정해야 하고, 그 판단에는 '어디까지 진행됐는지'가 필요하다.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .plan import RenderPlan
from .util import (LOG, CommandRunner, atomic_write, iter_glob, read_text_or_none,
                   staged_path)


@dataclass
class ApplyStep:
    kind: str  # file | command | service | cleanup
    name: str
    ok: bool
    detail: str = ""
    changed: bool = False
    skipped: bool = False


@dataclass
class ApplyLog:
    steps: list[ApplyStep] = field(default_factory=list)
    ok: bool = True
    aborted_at: str | None = None
    changed_files: list[str] = field(default_factory=list)

    def add(self, step: ApplyStep) -> None:
        self.steps.append(step)
        if not step.ok and not step.skipped:
            self.ok = False
            if self.aborted_at is None:
                self.aborted_at = f"{step.kind}:{step.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "aborted_at": self.aborted_at,
            "changed_files": self.changed_files,
            "steps": [asdict(step) for step in self.steps],
        }

    def render(self) -> str:
        lines = []
        for step in self.steps:
            status = "SKIP" if step.skipped else ("OK" if step.ok else "FAIL")
            mark = " *" if step.changed else ""
            lines.append(f"[{status:4}] {step.kind:7} {step.name}{mark}"
                         + (f" — {step.detail}" if step.detail else ""))
        return "\n".join(lines)


def _write_files(plan: RenderPlan, log: ApplyLog, dry_run: bool,
                 root: str | None = None) -> bool:
    for target in sorted(plan.files, key=lambda t: t.path):
        rendered = target.rendered()
        changed = read_text_or_none(staged_path(target.path, root)) != rendered
        if dry_run:
            log.add(ApplyStep("file", target.path, True, "dry-run", changed, skipped=True))
            continue
        try:
            atomic_write(target.path, rendered, target.mode, root=root)
            log.add(ApplyStep("file", target.path, True, "", changed))
            if changed:
                log.changed_files.append(target.path)
        except OSError as exc:
            log.add(ApplyStep("file", target.path, False, str(exc), changed))
            return False
    return True


def _cleanup(plan: RenderPlan, log: ApplyLog, dry_run: bool, root: str | None = None) -> None:
    """이번 계획에 없는 우리 소유 파일을 제거한다.

    VLAN 하나를 정책에서 지웠는데 드롭인 파일이 남아 있으면, 다음 부팅에 유령
    설정이 되살아난다. 이 정리는 선언형 desired state의 필수 조건이다.
    """
    planned = {str(staged_path(target.path, root)) for target in plan.files}
    for pattern in plan.owned_globs:
        for child in iter_glob(pattern, root):
            if str(child) in planned:
                continue
            if dry_run:
                log.add(ApplyStep("cleanup", str(child), True, "dry-run", True, skipped=True))
                continue
            try:
                child.unlink()
                log.add(ApplyStep("cleanup", str(child), True, "제거", True))
            except OSError as exc:
                # 정리 실패는 치명적이지 않다. 경고만 남긴다.
                log.add(ApplyStep("cleanup", str(child), True, f"제거 실패: {exc}", False))


def apply_plan(plan: RenderPlan, runner: CommandRunner, *, dry_run: bool = False,
               root: str | None = None) -> ApplyLog:
    log = ApplyLog()
    LOG.info("적용 시작 (파일 %d, 명령 %d, 서비스 %d, dry_run=%s)",
             len(plan.files), len(plan.apply_commands), len(plan.services), dry_run)

    if not _write_files(plan, log, dry_run, root):
        return log
    _cleanup(plan, log, dry_run, root)

    for command in plan.apply_commands:
        name = command.description or command.display()
        if dry_run:
            log.add(ApplyStep("command", command.display(), True, "dry-run", skipped=True))
            continue
        result = runner.run(list(command.argv), stdin=command.stdin, timeout=command.timeout)
        if result.ok:
            log.add(ApplyStep("command", name, True, "", True))
            continue
        if command.allow_fail:
            log.add(ApplyStep("command", name, True, f"무시된 실패: {result.summary()}",
                              False, skipped=True))
            continue
        log.add(ApplyStep("command", name, False, result.summary()))
        return log

    for service in plan.services:
        if dry_run:
            log.add(ApplyStep("service", f"{service.action} {service.unit}", True, "dry-run",
                              skipped=True))
            continue
        result = runner.run(["systemctl", service.action, service.unit], timeout=90.0)
        if result.ok:
            log.add(ApplyStep("service", f"{service.action} {service.unit}", True, "", True))
            continue
        if service.ignore_missing and "not found" in (result.stderr or "").lower():
            log.add(ApplyStep("service", f"{service.action} {service.unit}", True,
                              "유닛 없음 (건너뜀)", False, skipped=True))
            continue
        log.add(ApplyStep("service", f"{service.action} {service.unit}", False, result.summary()))
        return log

    LOG.info("적용 완료 (변경 파일 %d개)", len(log.changed_files))
    return log
