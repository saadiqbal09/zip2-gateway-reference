"""설정 스냅샷과 복구.

적용 전에 '되돌릴 수 있는 지점'을 만든다. 스냅샷은 두 가지를 담는다.

1. 우리가 관리하는 파일들의 이전 내용(없었으면 '없었음'이라는 사실 자체)
2. 그 파일들을 되살린 뒤 실행할 복구 명령 목록

2번이 중요하다. 복구는 적용과 다른 프로세스(systemd 트랜지언트 유닛)에서
실행되므로, 그 시점에 원래 정책 객체가 없다. 그래서 복구에 필요한 모든 것을
스냅샷 자체에 적어 둔다. 스냅샷 디렉터리만 있으면 누구든 복구할 수 있다.

진단용으로 적용 직전의 커널 상태(주소, 경로, 룰셋, 터널)도 함께 덤프한다.
사후에 "무엇이 어떻게 달라졌나"를 다투지 않기 위한 근거다.
"""
from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .errors import RollbackError
from .paths import (
    KEA_DHCP4_FILE,
    MOOKER_ROUTER_BIN,
    NFT_BRIDGE_FILE,
    NFT_INET_FILE,
    QOS_STATE_FILE,
    SNAPSHOT_DIR,
    UNBOUND_CONF_FILE,
    UNIT_KEA4,
    UNIT_UNBOUND,
)
from .plan import RenderPlan
from .state import now_iso
from .util import LOG, CommandRunner, atomic_write, iter_glob, staged_path

MANIFEST_NAME = "manifest.json"
FILES_SUBDIR = "files"
DIAGNOSTIC_NAME = "pre-apply-state.txt"
RETENTION = 10

DIAGNOSTIC_COMMANDS = (
    ("ip", "-details", "-json", "addr", "show"),
    ("ip", "-json", "route", "show", "table", "all"),
    ("ip", "-json", "rule", "show"),
    ("nft", "list", "ruleset"),
    ("wg", "show", "all", "dump"),
    ("tc", "-s", "qdisc", "show"),
    ("networkctl", "status", "--no-pager"),
    ("systemctl", "is-active", UNIT_KEA4, UNIT_UNBOUND, "systemd-networkd.service"),
)


@dataclass
class FileRecord:
    path: str
    existed: bool
    mode: int | None = None
    stored_as: str | None = None
    sha256: str | None = None


@dataclass
class SnapshotManifest:
    snapshot_id: str
    created_at: str
    reason: str
    from_revision: int | None
    to_revision: int | None
    files: list[FileRecord] = field(default_factory=list)
    owned_globs: list[str] = field(default_factory=list)
    restore_commands: list[list[str]] = field(default_factory=list)
    restore_services: list[list[str]] = field(default_factory=list)
    had_inet_table: bool = False
    had_bridge_table: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["files"] = [asdict(record) if not isinstance(record, dict) else record
                         for record in self.files]
        return data

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SnapshotManifest":
        files = [FileRecord(**record) for record in data.get("files", [])]
        payload = {key: value for key, value in data.items() if key != "files"}
        return SnapshotManifest(files=files, **payload)


def _sha256(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _table_exists(runner: CommandRunner, family: str, name: str) -> bool:
    return runner.run(["nft", "list", "table", family, name], timeout=10.0).ok


def create(
    plan: RenderPlan,
    runner: CommandRunner,
    *,
    reason: str,
    from_revision: int | None,
    to_revision: int | None,
    snapshot_root: str | Path = SNAPSHOT_DIR,
    file_root: str | None = None,
) -> SnapshotManifest:
    snapshot_id = f"{int(time.time())}-r{to_revision or 0}"
    root = Path(snapshot_root) / snapshot_id
    (root / FILES_SUBDIR).mkdir(parents=True, exist_ok=True)

    records: list[FileRecord] = []
    # QoS는 /run 아래 런타임 파일이지만 복구에 필요하므로 스냅샷에 포함한다.
    paths = sorted({*plan.managed_paths,
                    *(target.path for target in plan.persistent_files()),
                    QOS_STATE_FILE})
    for index, path in enumerate(paths):
        source = Path(staged_path(path, file_root))
        if not source.exists():
            records.append(FileRecord(path=path, existed=False))
            continue
        stored_as = f"{index:03d}_{source.name}"
        try:
            content = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            LOG.warning("스냅샷: %s 를 텍스트로 읽지 못해 바이너리 복사한다 (%s)", path, exc)
            shutil.copy2(source, root / FILES_SUBDIR / stored_as)
            records.append(FileRecord(path=path, existed=True,
                                      mode=source.stat().st_mode & 0o777, stored_as=stored_as))
            continue
        (root / FILES_SUBDIR / stored_as).write_text(content, encoding="utf-8")
        records.append(FileRecord(path=path, existed=True, mode=source.stat().st_mode & 0o777,
                                  stored_as=stored_as, sha256=_sha256(content)))

    had_inet = _table_exists(runner, "inet", "mooker")
    had_bridge = _table_exists(runner, "bridge", "mooker_l2")

    manifest = SnapshotManifest(
        snapshot_id=snapshot_id,
        created_at=now_iso(),
        reason=reason,
        from_revision=from_revision,
        to_revision=to_revision,
        files=records,
        owned_globs=list(plan.owned_globs),
        had_inet_table=had_inet,
        had_bridge_table=had_bridge,
    )
    manifest.restore_commands, manifest.restore_services = _build_restore_steps(manifest)

    atomic_write(root / MANIFEST_NAME,
                 json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False) + "\n", 0o640)
    _dump_diagnostics(root, runner)
    _prune(Path(snapshot_root))
    LOG.info("스냅샷 생성 %s (파일 %d개, inet=%s bridge=%s)", snapshot_id, len(records),
             had_inet, had_bridge)
    return manifest


def _build_restore_steps(manifest: SnapshotManifest) -> tuple[list[list[str]], list[list[str]]]:
    """복구 시 파일 복원 후 실행할 명령을 결정한다.

    이전 상태에 우리 테이블/설정이 아예 없었던 경우(최초 적용)를 반드시 구분해야
    한다. 파일만 지우고 끝내면 커널에는 방화벽 테이블이 그대로 남는다.
    """
    by_path = {record.path: record for record in manifest.files}
    commands: list[list[str]] = [
        ["sysctl", "--system"],
        ["netplan", "generate"],
        ["netplan", "apply"],
        ["networkctl", "reload"],
    ]

    inet_record = by_path.get(NFT_INET_FILE)
    if inet_record and inet_record.existed:
        commands.append(["nft", "-f", NFT_INET_FILE])
    elif manifest.had_inet_table:
        commands.append(["nft", "delete", "table", "inet", "mooker"])

    bridge_record = by_path.get(NFT_BRIDGE_FILE)
    if bridge_record and bridge_record.existed:
        commands.append(["nft", "-f", NFT_BRIDGE_FILE])
    elif manifest.had_bridge_table:
        commands.append(["nft", "delete", "table", "bridge", "mooker_l2"])

    services: list[list[str]] = []
    kea_record = by_path.get(KEA_DHCP4_FILE)
    if kea_record is not None:
        services.append(["restart" if kea_record.existed else "stop", UNIT_KEA4])
    unbound_record = by_path.get(UNBOUND_CONF_FILE)
    if unbound_record is not None:
        services.append(["restart" if unbound_record.existed else "stop", UNIT_UNBOUND])

    # QoS는 파일이 아니라 커널 상태다. 이전 파라미터가 남아 있으면 그대로 되돌리고,
    # 없으면 shaping을 해제한다(무제한이 잘못된 상한보다 안전하다).
    commands.append([MOOKER_ROUTER_BIN, "restore-qos", "--snapshot", manifest.snapshot_id])
    commands.append([MOOKER_ROUTER_BIN, "restore-dynamic"])
    return commands, services


def _dump_diagnostics(root: Path, runner: CommandRunner) -> None:
    chunks: list[str] = [f"# pre-apply diagnostics {now_iso()}"]
    for argv in DIAGNOSTIC_COMMANDS:
        result = runner.run(list(argv), timeout=15.0)
        chunks.append(f"\n===== {' '.join(argv)} (rc={result.returncode}) =====")
        chunks.append(result.stdout.strip() or result.stderr.strip())
    try:
        atomic_write(root / DIAGNOSTIC_NAME, "\n".join(chunks) + "\n", 0o640)
    except OSError as exc:  # 진단 실패가 적용을 막아서는 안 된다
        LOG.warning("진단 덤프 실패: %s", exc)


def _prune(snapshot_root: Path, keep: int = RETENTION) -> None:
    try:
        entries = sorted(
            (path for path in snapshot_root.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
        )
    except OSError:
        return
    for path in entries[:-keep] if len(entries) > keep else []:
        shutil.rmtree(path, ignore_errors=True)


def load(snapshot_id: str, snapshot_root: str | Path = SNAPSHOT_DIR) -> SnapshotManifest:
    path = Path(snapshot_root) / snapshot_id / MANIFEST_NAME
    try:
        return SnapshotManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise RollbackError(f"스냅샷 매니페스트를 읽을 수 없다: {path} ({exc})") from exc


def latest(snapshot_root: str | Path = SNAPSHOT_DIR) -> str | None:
    try:
        entries = sorted(
            (path for path in Path(snapshot_root).iterdir() if (path / MANIFEST_NAME).exists()),
            key=lambda path: path.stat().st_mtime,
        )
    except OSError:
        return None
    return entries[-1].name if entries else None


def restore(
    snapshot_id: str,
    runner: CommandRunner,
    *,
    snapshot_root: str | Path = SNAPSHOT_DIR,
    dry_run: bool = False,
    file_root: str | None = None,
) -> dict[str, Any]:
    """스냅샷으로 되돌린다. 부분 실패해도 최대한 진행하고 전부 기록한다.

    복구는 '실패하면 안 되는' 경로다. 중간에 예외로 빠져나가면 절반만 되돌아간
    상태로 방치된다. 그래서 각 단계를 개별적으로 시도하고 결과를 모아서 보고한다.
    """
    manifest = load(snapshot_id, snapshot_root)
    root = Path(snapshot_root) / snapshot_id
    report: dict[str, Any] = {"snapshot_id": snapshot_id, "files": [], "commands": [],
                              "services": [], "errors": [], "dry_run": dry_run}

    for record in manifest.files:
        target = Path(staged_path(record.path, file_root))
        try:
            if record.existed and record.stored_as:
                content = (root / FILES_SUBDIR / record.stored_as).read_text(encoding="utf-8")
                if not dry_run:
                    atomic_write(record.path, content, record.mode or 0o640, root=file_root)
                report["files"].append({"path": record.path, "action": "restored"})
            else:
                if target.exists() and not dry_run:
                    target.unlink()
                report["files"].append({"path": record.path, "action": "removed"})
        except OSError as exc:
            message = f"파일 복구 실패 {record.path}: {exc}"
            report["errors"].append(message)
            LOG.error(message)

    # 스냅샷 시점에 없던 파일이 우리 소유 패턴에 남아 있으면 제거한다.
    # (되돌린 정책이 만들지 않았던 드롭인 등)
    snapshot_paths = {str(staged_path(record.path, file_root)) for record in manifest.files}
    for pattern in manifest.owned_globs:
        for child in iter_glob(pattern, file_root):
            if str(child) in snapshot_paths or dry_run:
                continue
            try:
                child.unlink()
                report["files"].append({"path": str(child), "action": "removed(잔여)"})
            except OSError as exc:
                report["errors"].append(f"잔여 파일 정리 실패 {child}: {exc}")

    for argv in manifest.restore_commands:
        if dry_run:
            report["commands"].append({"argv": argv, "rc": "dry-run"})
            continue
        result = runner.run(argv, timeout=90.0)
        report["commands"].append({"argv": argv, "rc": result.returncode,
                                   "detail": result.summary(200)})
        if not result.ok:
            LOG.warning("복구 명령 실패(계속 진행) %s: %s", " ".join(argv), result.summary())

    for action, unit in manifest.restore_services:
        if dry_run:
            report["services"].append({"unit": unit, "action": action, "rc": "dry-run"})
            continue
        result = runner.run(["systemctl", action, unit], timeout=60.0)
        report["services"].append({"unit": unit, "action": action, "rc": result.returncode,
                                   "detail": result.summary(200)})

    LOG.info("스냅샷 복구 완료 %s (오류 %d건)", snapshot_id, len(report["errors"]))
    return report
