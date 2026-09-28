"""commit-confirm: 적용 후 확인이 없으면 스스로 되돌린다.

원격에서 네트워크 설정을 바꿀 때 가장 위험한 실패는 "명령은 성공했는데 접속이
끊겼다"이다. 이 경우 Agent도 CLI도 아무것도 할 수 없다. 그래서 되돌리는 주체를
적용 프로세스 밖에 둔다.

적용 **직전에** systemd 트랜지언트 타이머를 예약한다.

    systemd-run --unit=mooker-router-rollback-<snap> --on-active=<초> --collect \
                /usr/local/lib/mooker-router/rollback <snap>

- 적용 도중 프로세스가 죽어도, 커널이 멈춰도, 회선이 끊겨도 타이머는 남는다.
- 검증을 통과하고 중앙 confirm까지 받으면 타이머를 해제한다.
- 검증 실패면 타이머를 기다리지 않고 즉시 복구한 뒤 해제한다.

systemd-run을 쓸 수 없는 환경(컨테이너 등)에서는 분리된 자식 프로세스로 대체한다.
동일한 보장은 아니므로 그 사실을 상태에 남긴다.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .paths import ROLLBACK_HELPER, ROLLBACK_UNIT_PREFIX, RUN_DIR
from .util import LOG, CommandRunner


@dataclass
class Guard:
    unit: str
    deadline_epoch: float
    mechanism: str  # systemd | fallback

    @property
    def seconds_left(self) -> float:
        return max(0.0, self.deadline_epoch - time.time())


def unit_name(snapshot_id: str) -> str:
    safe = snapshot_id.replace("/", "_")
    return f"{ROLLBACK_UNIT_PREFIX}-{safe}"


def arm(snapshot_id: str, timeout_s: int, runner: CommandRunner,
        helper: str = ROLLBACK_HELPER) -> Guard:
    unit = unit_name(snapshot_id)
    deadline = time.time() + timeout_s

    if runner.which("systemd-run") and Path(helper).exists():
        result = runner.run([
            "systemd-run",
            f"--unit={unit}",
            f"--on-active={timeout_s}s",
            "--collect",
            f"--description=Mooker Router 자동 복구 ({snapshot_id})",
            helper, snapshot_id,
        ], timeout=30.0)
        if result.ok:
            LOG.warning("자동 복구 예약: %s.timer, %d초 내 confirm 필요", unit, timeout_s)
            return Guard(unit, deadline, "systemd")
        LOG.error("systemd-run 예약 실패, 대체 방식 사용: %s", result.summary())

    # 대체 경로: 이중 fork로 세션을 분리한 자식이 sleep 후 복구를 실행한다.
    if not Path(helper).exists():
        LOG.error("복구 헬퍼가 없다: %s", helper)
    pid = _spawn_fallback(snapshot_id, timeout_s, helper)
    LOG.warning("자동 복구 예약(대체 방식, pid=%s): %d초", pid, timeout_s)
    return Guard(f"fallback:{pid}", deadline, "fallback")


def _spawn_fallback(snapshot_id: str, timeout_s: int, helper: str) -> int:
    Path(RUN_DIR).mkdir(parents=True, exist_ok=True)
    marker = Path(RUN_DIR) / f"rollback-{snapshot_id}.pid"
    command = (
        f'sleep {int(timeout_s)}; '
        f'if [ -f "{marker}" ]; then rm -f "{marker}"; '
        f'exec {helper} {snapshot_id}; fi'
    )
    process = subprocess.Popen(
        ["setsid", "sh", "-c", command],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    marker.write_text(f"{process.pid}\n", encoding="utf-8")
    return process.pid


def disarm(guard_unit: str, runner: CommandRunner) -> bool:
    """예약을 해제한다. 실패해도 예외를 던지지 않는다(호출자가 상태로 판단한다)."""
    if guard_unit.startswith("fallback:"):
        pid = guard_unit.split(":", 1)[1]
        for marker in Path(RUN_DIR).glob("rollback-*.pid"):
            try:
                if marker.read_text(encoding="utf-8").strip() == pid:
                    marker.unlink()
            except OSError:
                pass
        try:
            os.kill(int(pid), 15)
        except (OSError, ValueError):
            pass
        LOG.info("자동 복구 예약 해제(대체 방식 pid=%s)", pid)
        return True

    stopped = runner.run(["systemctl", "stop", f"{guard_unit}.timer"], timeout=30.0)
    runner.run(["systemctl", "reset-failed", f"{guard_unit}.timer"], timeout=15.0)
    runner.run(["systemctl", "reset-failed", f"{guard_unit}.service"], timeout=15.0)
    if stopped.ok:
        LOG.info("자동 복구 예약 해제: %s.timer", guard_unit)
    else:
        LOG.error("자동 복구 예약 해제 실패: %s (%s)", guard_unit, stopped.summary())
    return stopped.ok


def list_armed(runner: CommandRunner) -> list[str]:
    result = runner.run(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"],
                        timeout=20.0)
    units = []
    for line in (result.stdout or "").splitlines():
        for token in line.split():
            if token.startswith(ROLLBACK_UNIT_PREFIX) and token.endswith(".timer"):
                units.append(token[: -len(".timer")])
    for marker in Path(RUN_DIR).glob("rollback-*.pid"):
        units.append(f"fallback:{marker.read_text(encoding='utf-8').strip()}")
    return sorted(set(units))
