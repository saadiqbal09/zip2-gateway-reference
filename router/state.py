"""로컬 적용 상태 저장소.

중앙이 보낸 것(desired)과 장비에 실제로 반영된 것(applied), 그리고 아직 확정되지
않은 것(pending)을 분리해 기록한다. 이 구분이 없으면 "정책은 보냈는데 적용됐는지
모르는" 상태가 되고, 운영 화면의 정책 revision이 거짓말을 하게 된다.

파일 하나(state.json)만 쓰고, 쓰기는 항상 원자적이다. 적용 작업은 파일 락으로
직렬화한다 — Agent 주기 동작과 운영자의 수동 CLI 실행이 겹치는 일이 실제로
자주 일어난다.
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .errors import StateError
from .paths import LOCK_FILE, STATE_FILE
from .util import LOG, atomic_write


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class PendingApply:
    """검증은 통과했으나 아직 confirm되지 않은 적용."""

    revision: int
    snapshot_id: str
    policy_digest: str
    armed_unit: str
    deadline_epoch: float
    # 누가 확정해야 하는가(central/manual). Agent가 자동 confirm할지 판단한다.
    confirm_mode: str = "central"
    started_at: str = field(default_factory=now_iso)

    def seconds_left(self) -> float:
        return max(0.0, self.deadline_epoch - time.time())


@dataclass
class RouterState:
    schema: int = 1
    desired_revision: int | None = None
    applied_revision: int | None = None
    confirmed_revision: int | None = None
    last_good_snapshot: str | None = None
    pending: PendingApply | None = None
    last_apply: dict[str, Any] = field(default_factory=dict)
    last_error: str | None = None
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["pending"] = asdict(self.pending) if self.pending else None
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "RouterState":
        pending_raw = data.get("pending")
        pending = None
        if isinstance(pending_raw, dict):
            try:
                pending = PendingApply(**pending_raw)
            except TypeError as exc:
                raise StateError(f"state.json의 pending 블록이 손상되었다: {exc}") from exc
        known = {
            "schema", "desired_revision", "applied_revision", "confirmed_revision",
            "last_good_snapshot", "last_apply", "last_error", "updated_at",
        }
        kwargs = {key: data[key] for key in known if key in data}
        return RouterState(pending=pending, **kwargs)


class StateStore:
    def __init__(self, path: str | Path = STATE_FILE):
        self.path = Path(path)

    def load(self) -> RouterState:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return RouterState()
        except OSError as exc:
            raise StateError(f"state.json을 읽을 수 없다: {exc}") from exc
        try:
            return RouterState.from_dict(json.loads(raw))
        except json.JSONDecodeError as exc:
            # 손상된 상태 파일로 적용을 멈추기보다, 백업하고 초기화하는 편이
            # 현장 복구에 유리하다. 다만 흔적은 반드시 남긴다.
            backup = self.path.with_suffix(f".corrupt.{int(time.time())}")
            try:
                self.path.replace(backup)
            except OSError:
                pass
            LOG.error("state.json 손상: %s (백업 %s)", exc, backup)
            return RouterState(last_error=f"state.json 손상 후 초기화됨: {exc}")

    def save(self, state: RouterState) -> None:
        state.updated_at = now_iso()
        # 경로는 주입 가능하다(테스트/대체 루트). 하드코딩된 STATE_DIR을 쓰지 않는다.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self.path, json.dumps(state.to_dict(), indent=2, ensure_ascii=False) + "\n",
                     mode=0o640)


@contextmanager
def apply_lock(timeout_s: float = 30.0, path: str | Path = LOCK_FILE) -> Iterator[None]:
    """적용 작업 직렬화. 이미 적용 중이면 기다렸다가 실패한다."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "w", encoding="utf-8")
    deadline = time.time() + timeout_s
    while True:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                handle.close()
                raise
            if time.time() >= deadline:
                handle.close()
                raise StateError(
                    f"다른 적용 작업이 진행 중이다({path}). {timeout_s:.0f}초 대기 후 포기했다.")
            time.sleep(0.5)
    try:
        handle.write(f"pid={os.getpid()} at={now_iso()}\n")
        handle.flush()
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()
