"""자동 복구 진입점.

systemd 트랜지언트 타이머가 이 모듈을 호출한다. 적용 프로세스와 완전히 분리되어
있어야 하므로 의존성을 최소로 유지한다: 스냅샷 디렉터리만 있으면 동작한다.

    /usr/local/lib/mooker-router/rollback <snapshot_id>
      -> python3 -m router.rollback_entry <snapshot_id>

여기까지 실행됐다는 것은 "적용은 됐지만 확정되지 않았다"는 뜻이다. 원인은
회선 단절, 관리 경로 상실, Agent 크래시 중 하나다. 어느 쪽이든 되돌리는 것이
맞다.
"""
from __future__ import annotations

import sys

from . import snapshot as snapshot_module
from .commitguard import disarm
from .dynamic import DynamicStore, sync as sync_dynamic
from .paths import LOG_FILE, SNAPSHOT_DIR
from .state import StateStore
from .util import LOG, SubprocessRunner, setup_logging


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    setup_logging(True, LOG_FILE)
    if not argv:
        print("usage: python3 -m router.rollback_entry <snapshot_id>", file=sys.stderr)
        return 2
    snapshot_id = argv[0]
    runner = SubprocessRunner()
    store = StateStore()
    state = store.load()

    LOG.error("commit-confirm 타임아웃: revision %s 미확정 → 스냅샷 %s로 자동 복구한다",
              state.pending.revision if state.pending else "?", snapshot_id)

    try:
        report = snapshot_module.restore(snapshot_id, runner, snapshot_root=SNAPSHOT_DIR)
    except Exception as exc:  # 복구 경로에서는 어떤 예외도 삼키고 기록한다
        LOG.critical("자동 복구 실패: %s — 콘솔 개입이 필요하다", exc)
        state.last_error = f"자동 복구 실패: {exc}"
        store.save(state)
        return 1

    sync_dynamic(runner, DynamicStore())

    manifest = snapshot_module.load(snapshot_id, SNAPSHOT_DIR)
    if state.pending:
        disarm(state.pending.armed_unit, runner)
        rolled_back_revision = state.pending.revision
        state.pending = None
    else:
        rolled_back_revision = manifest.to_revision
    state.applied_revision = manifest.from_revision
    state.last_error = (f"revision {rolled_back_revision} 미확정으로 자동 복구됨 "
                        f"(snapshot {snapshot_id})")
    state.last_apply = {
        "revision": rolled_back_revision,
        "snapshot_id": snapshot_id,
        "auto_rollback": True,
        "errors": report.get("errors", []),
    }
    store.save(state)

    if report.get("errors"):
        LOG.critical("자동 복구가 일부 실패했다: %s", report["errors"])
        return 1
    LOG.warning("자동 복구 완료. revision %s로 되돌아갔다", manifest.from_revision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
