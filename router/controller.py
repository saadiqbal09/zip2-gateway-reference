"""NetworkController: 정책 적용 오케스트레이션.

Agent와 CLI가 쓰는 유일한 진입점이다. 순서가 이 클래스의 본질이다.

    서명 검증 → 스키마/베이스라인 검증 → 렌더링 → 사전검사(staging)
    → 스냅샷 → **자동 복구 예약** → 적용 → 연결 검증
    → (중앙 confirm) → 확정  /  (실패) → 즉시 복구

자동 복구 예약을 적용 '앞'에 두는 것이 핵심이다. 적용 중간에 회선이 끊기거나
프로세스가 죽어도 타이머는 살아 있어 장비가 스스로 돌아온다. 예약을 뒤에 두면
바로 그 사고를 막지 못한다.

각 단계는 실패 시 '아무것도 바뀌지 않음' 또는 '이전 상태로 복구됨' 중 하나를
보장한다. 어중간한 상태로 끝나는 경로를 남기지 않는다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import commitguard, precheck as precheck_module, snapshot as snapshot_module
from .apply import ApplyLog, apply_plan
from .context import RenderContext
from .dynamic import DynamicStore, sync as sync_dynamic
from .envelope import TrustStore, VerifiedEnvelope, verify_envelope
from .errors import (
    ApplyError,
    PrecheckError,
    RollbackError,
    RouterError,
    StateError,
    VerifyFailed,
)
from .model import RouterPolicy
from .paths import (
    LOCK_FILE,
    POLICY_CACHE,
    ROLLBACK_HELPER,
    POLICY_LAST_GOOD,
    QOS_STATE_FILE,
    SNAPSHOT_DIR,
    TRUST_DIR,
)
from .plan import RenderPlan
from .render import render_all
from .state import PendingApply, RouterState, StateStore, apply_lock, now_iso
from .util import LOG, CommandRunner, SubprocessRunner, atomic_write
from .verify import NetworkProbes, VerifyReport, verify as verify_policy


@dataclass
class ApplyReport:
    ok: bool
    stage: str
    message: str = ""
    revision: int | None = None
    snapshot_id: str | None = None
    diff: str = ""
    precheck: dict[str, Any] = field(default_factory=dict)
    apply_log: dict[str, Any] = field(default_factory=dict)
    verify: dict[str, Any] = field(default_factory=dict)
    rollback: dict[str, Any] = field(default_factory=dict)
    pending_seconds: float | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "message": self.message,
            "revision": self.revision,
            "snapshot_id": self.snapshot_id,
            "precheck": self.precheck,
            "apply": self.apply_log,
            "verify": self.verify,
            "rollback": self.rollback,
            "pending_seconds": self.pending_seconds,
            "notes": self.notes,
            "at": now_iso(),
        }

    def summary(self) -> str:
        head = f"{'성공' if self.ok else '실패'} [{self.stage}] revision={self.revision}"
        return f"{head}\n{self.message}" if self.message else head


class NetworkController:
    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        gateway_id: str | None = None,
        state_store: StateStore | None = None,
        trust: TrustStore | None = None,
        snapshot_root: str = SNAPSHOT_DIR,
        context: RenderContext | None = None,
        dynamic_store: DynamicStore | None = None,
        file_root: str | None = None,
        rollback_helper: str = ROLLBACK_HELPER,
        lock_path: str = LOCK_FILE,
        probes: "NetworkProbes | None" = None,
    ):
        self.runner = runner or SubprocessRunner()
        self.gateway_id = gateway_id
        self.state_store = state_store or StateStore()
        self.trust = trust or TrustStore(TRUST_DIR)
        self.snapshot_root = snapshot_root
        self._context = context
        self.dynamic_store = dynamic_store or DynamicStore()
        # 테스트/검토용 대체 루트. None이면 실제 파일시스템에 쓴다.
        self.file_root = file_root
        self.rollback_helper = rollback_helper
        self.lock_path = lock_path
        # 정책 캐시는 상태 파일과 같은 디렉터리에 둔다. 상태와 정책이 서로 다른
        # 위치로 갈라지면 복구 시 어느 쪽이 맞는지 알 수 없다.
        self.state_dir = Path(self.state_store.path).parent
        self.policy_cache = self.state_dir / Path(POLICY_CACHE).name
        self.policy_last_good = self.state_dir / Path(POLICY_LAST_GOOD).name
        self.probes = probes or NetworkProbes()

    # ------------------------------------------------------------------
    # 준비 단계
    # ------------------------------------------------------------------
    def context(self) -> RenderContext:
        if self._context is None:
            self._context = RenderContext.discover(self.runner)
            LOG.info("환경 탐지: %s", self._context.detected)
        return self._context

    def _verify_envelope(self, raw: bytes | str | dict, *, force: bool,
                         state: RouterState) -> VerifiedEnvelope:
        min_revision = None if force else state.applied_revision
        return verify_envelope(
            raw,
            trust=self.trust,
            expected_gateway_id=self.gateway_id,
            min_revision=min_revision,
        )

    def build(self, raw: bytes | str | dict, *, force: bool = False) -> tuple[RouterPolicy, RenderPlan]:
        """검증 + 렌더링만 수행한다(시스템 변경 없음)."""
        state = self.state_store.load()
        verified = self._verify_envelope(raw, force=force, state=state)
        plan = render_all(verified.policy, self.context())
        return verified.policy, plan

    def plan(self, raw: bytes | str | dict, *, force: bool = False) -> ApplyReport:
        """``mooker-router plan``: 무엇이 바뀔지 보여주고 사전검사까지 돌린다."""
        try:
            policy, plan = self.build(raw, force=force)
        except RouterError as exc:
            return ApplyReport(False, self._stage_of(exc), str(exc))
        report = precheck_module.run(plan, self.runner, file_root=self.file_root)
        return ApplyReport(
            ok=report.ok,
            stage="precheck",
            message=report.render(),
            revision=policy.revision,
            diff=plan.diff() or "(디스크와 동일 — 변경 없음)",
            precheck=report.to_dict(),
            notes=plan.notes,
        )

    # ------------------------------------------------------------------
    # 적용
    # ------------------------------------------------------------------
    def apply(self, raw: bytes | str | dict, *, force: bool = False,
              dry_run: bool = False, reason: str = "central policy") -> ApplyReport:
        with apply_lock(path=self.lock_path):
            return self._apply_locked(raw, force=force, dry_run=dry_run, reason=reason)

    def _apply_locked(self, raw, *, force: bool, dry_run: bool, reason: str) -> ApplyReport:
        state = self.state_store.load()
        self._reconcile_pending(state)

        # 1) 서명/스키마/베이스라인
        try:
            verified = self._verify_envelope(raw, force=force, state=state)
        except RouterError as exc:
            state.last_error = f"{self._stage_of(exc)}: {exc}"
            self.state_store.save(state)
            return ApplyReport(False, self._stage_of(exc), str(exc))
        policy = verified.policy

        # 확정되지 않은 적용이 남아 있으면 새 정책을 얹지 않는다. 두 개의
        # 되돌림 지점이 겹치면 어디로 돌아가야 하는지 알 수 없게 된다.
        if state.pending and not force:
            return ApplyReport(
                False, "pending",
                f"revision {state.pending.revision} 적용이 아직 확정되지 않았다 "
                f"(남은 시간 {state.pending.seconds_left():.0f}s). "
                f"confirm 또는 rollback 후 다시 시도한다.",
                revision=policy.revision,
                snapshot_id=state.pending.snapshot_id,
                pending_seconds=state.pending.seconds_left(),
            )

        # 2) 렌더링
        try:
            plan = render_all(policy, self.context())
        except RouterError as exc:
            state.last_error = f"render: {exc}"
            self.state_store.save(state)
            return ApplyReport(False, "render", str(exc), revision=policy.revision)

        diff = plan.diff(self.file_root)

        # 3) 사전검사 — 여기까지는 시스템 무변경
        precheck_report = precheck_module.run(plan, self.runner,
                                              file_root=self.file_root)
        if not precheck_report.ok:
            message = "사전검사 실패 — 시스템은 변경되지 않았다\n" + precheck_report.render()
            state.last_error = message.splitlines()[0]
            self.state_store.save(state)
            return ApplyReport(False, "precheck", message, revision=policy.revision,
                               diff=diff, precheck=precheck_report.to_dict(), notes=plan.notes)

        if dry_run:
            return ApplyReport(True, "dry-run",
                               "사전검사 통과. dry-run이므로 적용하지 않았다.\n"
                               + precheck_report.render(),
                               revision=policy.revision, diff=diff,
                               precheck=precheck_report.to_dict(), notes=plan.notes)

        if not diff and state.applied_revision == policy.revision and not state.pending:
            return ApplyReport(True, "no-change",
                               f"revision {policy.revision}이 이미 반영되어 있다(변경 없음).",
                               revision=policy.revision, precheck=precheck_report.to_dict())

        # 4) 스냅샷
        try:
            manifest = snapshot_module.create(
                plan, self.runner, reason=reason,
                from_revision=state.applied_revision, to_revision=policy.revision,
                snapshot_root=self.snapshot_root, file_root=self.file_root,
            )
        except OSError as exc:
            return ApplyReport(False, "snapshot", f"스냅샷 생성 실패: {exc}",
                               revision=policy.revision)

        state.desired_revision = policy.revision
        self.state_store.save(state)

        # 5) 자동 복구 예약 (적용 전에!)
        guard = commitguard.arm(manifest.snapshot_id, policy.commit_confirm.timeout_s,
                                self.runner, helper=self.rollback_helper)
        state.pending = PendingApply(
            revision=policy.revision,
            snapshot_id=manifest.snapshot_id,
            policy_digest=verified.policy_digest,
            armed_unit=guard.unit,
            deadline_epoch=guard.deadline_epoch,
            confirm_mode=policy.commit_confirm.mode,
        )
        self.state_store.save(state)
        notes = list(plan.notes)
        if guard.mechanism != "systemd":
            notes.append(
                "systemd 트랜지언트 타이머를 쓸 수 없어 대체 방식으로 복구를 예약했다. "
                "프로세스 종료에 대한 보장이 약하므로 원인을 확인해야 한다.")

        # 6) 적용
        apply_log = apply_plan(plan, self.runner, root=self.file_root)
        if not apply_log.ok:
            return self._fail_and_rollback(
                state, manifest.snapshot_id, guard.unit, policy,
                stage="apply",
                message=f"적용 실패({apply_log.aborted_at}) — 스냅샷으로 되돌린다\n"
                        + apply_log.render(),
                apply_log=apply_log, notes=notes,
            )

        # 7) 연결 검증
        verify_report = verify_policy(policy, self.runner, probes=self.probes)
        if not verify_report.ok:
            return self._fail_and_rollback(
                state, manifest.snapshot_id, guard.unit, policy,
                stage="verify",
                message="연결 검증 실패 — 즉시 되돌린다\n" + verify_report.render(),
                apply_log=apply_log, verify_report=verify_report, notes=notes,
            )

        # 8) 성공. 동적 셋 복원(테이블 교체로 비워졌다)
        dynamic_report = sync_dynamic(self.runner, self.dynamic_store)
        self._cache_policy(self.policy_cache, policy)
        state.applied_revision = policy.revision
        state.last_error = None
        state.last_apply = {
            "revision": policy.revision,
            "snapshot_id": manifest.snapshot_id,
            "digest": verified.policy_digest,
            "key_id": verified.key_id,
            "changed_files": apply_log.changed_files,
            "verify": verify_report.to_dict(),
            "dynamic": dynamic_report,
            "at": now_iso(),
        }

        if policy.commit_confirm.requires_confirm:
            self.state_store.save(state)
            who = "중앙" if policy.commit_confirm.mode == "central" else "운영자"
            LOG.warning("revision %s 적용됨. %ds 내 %s confirm이 없으면 자동 복구된다.",
                        policy.revision, policy.commit_confirm.timeout_s, who)
            hint = ("" if policy.commit_confirm.mode == "central"
                    else " 접속이 유지되면 `mooker-router confirm`을 실행한다.")
            return ApplyReport(
                True, "pending-confirm",
                f"적용 및 검증 통과. {who} confirm 대기 중 "
                f"(남은 시간 {state.pending.seconds_left():.0f}s). "
                f"확인이 없으면 자동으로 되돌아간다.{hint}",
                revision=policy.revision, snapshot_id=manifest.snapshot_id, diff=diff,
                precheck=precheck_report.to_dict(), apply_log=apply_log.to_dict(),
                verify=verify_report.to_dict(),
                pending_seconds=state.pending.seconds_left(), notes=notes,
            )

        commitguard.disarm(guard.unit, self.runner)
        state.pending = None
        state.confirmed_revision = policy.revision
        state.last_good_snapshot = manifest.snapshot_id
        self.state_store.save(state)
        self._cache_policy(self.policy_last_good, policy)
        return ApplyReport(
            True, "confirmed", "적용, 검증, 확정 완료.",
            revision=policy.revision, snapshot_id=manifest.snapshot_id, diff=diff,
            precheck=precheck_report.to_dict(), apply_log=apply_log.to_dict(),
            verify=verify_report.to_dict(), notes=notes,
        )

    def _fail_and_rollback(self, state: RouterState, snapshot_id: str, guard_unit: str,
                           policy: RouterPolicy, *, stage: str, message: str,
                           apply_log: ApplyLog | None = None,
                           verify_report: VerifyReport | None = None,
                           notes: list[str] | None = None) -> ApplyReport:
        rollback_report: dict[str, Any] = {}
        try:
            rollback_report = snapshot_module.restore(snapshot_id, self.runner,
                                                     snapshot_root=self.snapshot_root,
                                                     file_root=self.file_root)
        except RollbackError as exc:
            rollback_report = {"errors": [str(exc)]}
            LOG.error("복구 실패: %s", exc)
        commitguard.disarm(guard_unit, self.runner)
        sync_dynamic(self.runner, self.dynamic_store)

        state.pending = None
        state.desired_revision = policy.revision
        state.last_error = f"{stage}: {message.splitlines()[0]}"
        state.last_apply = {
            "revision": policy.revision,
            "snapshot_id": snapshot_id,
            "stage": stage,
            "rolled_back": True,
            "at": now_iso(),
        }
        self.state_store.save(state)
        return ApplyReport(
            False, stage, message, revision=policy.revision, snapshot_id=snapshot_id,
            apply_log=apply_log.to_dict() if apply_log else {},
            verify=verify_report.to_dict() if verify_report else {},
            rollback=rollback_report, notes=notes or [],
        )

    # ------------------------------------------------------------------
    # confirm / rollback / status
    # ------------------------------------------------------------------
    def confirm(self, revision: int | None = None) -> dict[str, Any]:
        with apply_lock(path=self.lock_path):
            state = self.state_store.load()
            if state.pending is None:
                return {"ok": False, "message": "확정 대기 중인 적용이 없다",
                        "applied_revision": state.applied_revision}
            if revision is not None and revision != state.pending.revision:
                return {"ok": False,
                        "message": f"대기 중인 revision은 {state.pending.revision}이다 "
                                   f"(요청 {revision})"}
            snapshot_id = state.pending.snapshot_id
            confirmed_revision = state.pending.revision
            disarmed = commitguard.disarm(state.pending.armed_unit, self.runner)
            state.pending = None
            state.confirmed_revision = confirmed_revision
            state.last_good_snapshot = snapshot_id
            self.state_store.save(state)
            try:
                self.policy_cache.replace(self.policy_last_good)
            except OSError:
                pass
            LOG.info("revision %s 확정. 자동 복구 예약 해제=%s", confirmed_revision, disarmed)
            return {"ok": True, "confirmed_revision": confirmed_revision,
                    "snapshot_id": snapshot_id, "guard_disarmed": disarmed,
                    "message": "확정 완료. 자동 복구 예약을 해제했다."
                               if disarmed else
                               "확정 기록은 남겼으나 예약 해제에 실패했다. 즉시 확인이 필요하다."}

    def rollback(self, *, reason: str = "operator request",
                 snapshot_id: str | None = None) -> dict[str, Any]:
        with apply_lock(path=self.lock_path):
            state = self.state_store.load()
            target = snapshot_id or (state.pending.snapshot_id if state.pending
                                     else state.last_good_snapshot
                                     or snapshot_module.latest(self.snapshot_root))
            if not target:
                return {"ok": False, "message": "되돌릴 스냅샷이 없다"}
            report = snapshot_module.restore(target, self.runner,
                                             snapshot_root=self.snapshot_root,
                                             file_root=self.file_root)
            if state.pending:
                commitguard.disarm(state.pending.armed_unit, self.runner)
                state.pending = None
            sync_dynamic(self.runner, self.dynamic_store)
            manifest = snapshot_module.load(target, self.snapshot_root)
            state.applied_revision = manifest.from_revision
            state.last_error = f"rollback: {reason}"
            self.state_store.save(state)
            LOG.warning("스냅샷 %s로 되돌렸다 (사유: %s)", target, reason)
            return {"ok": not report["errors"], "snapshot_id": target, "reason": reason,
                    "restored_revision": manifest.from_revision, "detail": report}

    def status(self) -> dict[str, Any]:
        state = self.state_store.load()
        changed = self._reconcile_pending(state)
        if changed:
            self.state_store.save(state)
        armed = commitguard.list_armed(self.runner)
        return {
            "desired_revision": state.desired_revision,
            "applied_revision": state.applied_revision,
            "confirmed_revision": state.confirmed_revision,
            "last_good_snapshot": state.last_good_snapshot,
            "pending": {
                "revision": state.pending.revision,
                "snapshot_id": state.pending.snapshot_id,
                "seconds_left": round(state.pending.seconds_left(), 1),
                "armed_unit": state.pending.armed_unit,
                "confirm_mode": state.pending.confirm_mode,
            } if state.pending else None,
            "armed_rollback_units": armed,
            "last_error": state.last_error,
            "last_apply": state.last_apply,
            "dynamic_elements": len(self.dynamic_store.load()),
            "updated_at": state.updated_at,
        }

    def _reconcile_pending(self, state: RouterState) -> bool:
        """이전 실행이 남긴 pending을 현실과 맞춘다.

        타이머가 이미 발동해 복구가 일어난 경우, state에는 pending이 그대로
        남아 있다. 이 상태를 방치하면 이후 모든 적용이 "확정되지 않은 적용이
        있다"며 거부된다.
        """
        if state.pending is None:
            return False
        if state.pending.seconds_left() > 0:
            return False
        armed = commitguard.list_armed(self.runner)
        if state.pending.armed_unit in armed:
            return False
        LOG.warning("확정되지 않은 revision %s의 예약이 만료되었다. 자동 복구가 수행된 것으로 본다.",
                    state.pending.revision)
        state.last_error = (f"revision {state.pending.revision} 미확정으로 자동 복구됨 "
                            f"(snapshot {state.pending.snapshot_id})")
        state.applied_revision = state.confirmed_revision
        state.pending = None
        return True

    # ------------------------------------------------------------------
    # 보조 동작
    # ------------------------------------------------------------------
    def restore_dynamic(self) -> dict[str, Any]:
        return sync_dynamic(self.runner, self.dynamic_store)

    def restore_qos(self, snapshot_id: str | None = None) -> dict[str, Any]:
        """스냅샷에 기록된 QoS 파라미터를 다시 tc에 적용한다.

        복구 경로에서 호출된다. 기록이 없으면 shaping을 해제한다 — 잘못된 상한을
        유지하는 것보다 무제한이 안전하다.
        """
        source = Path(QOS_STATE_FILE)
        if snapshot_id:
            candidate = (Path(self.snapshot_root) / snapshot_id / snapshot_module.FILES_SUBDIR)
            for path in sorted(candidate.glob("*qos.json")):
                source = path
                break
        try:
            state = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"ok": True, "message": "복원할 QoS 기록이 없다", "actions": []}

        actions: list[dict[str, Any]] = []
        for wan, entry in state.items():
            device = entry.get("device")
            if not device:
                continue
            if not entry.get("enabled"):
                for argv in (["tc", "qdisc", "del", "dev", device, "root"],
                             ["tc", "qdisc", "del", "dev", device, "ingress"]):
                    result = self.runner.run(argv, timeout=15.0)
                    actions.append({"wan": wan, "argv": argv, "rc": result.returncode})
                continue
            qdisc = entry.get("qdisc", "cake")
            upload = entry.get("upload_mbit")
            argv = ["tc", "qdisc", "replace", "dev", device, "root", qdisc]
            if qdisc == "cake" and upload:
                argv.extend(["bandwidth", f"{upload:g}mbit"])
            result = self.runner.run(argv, timeout=20.0)
            actions.append({"wan": wan, "argv": argv, "rc": result.returncode})
            ifb = entry.get("ifb")
            download = entry.get("download_mbit")
            if ifb and download:
                argv = ["tc", "qdisc", "replace", "dev", ifb, "root", qdisc]
                if qdisc == "cake":
                    argv.extend(["bandwidth", f"{download:g}mbit", "ingress", "wash"])
                result = self.runner.run(argv, timeout=20.0)
                actions.append({"wan": wan, "argv": argv, "rc": result.returncode})
        return {"ok": True, "source": str(source), "actions": actions}

    def _cache_policy(self, path: str | Path, policy: RouterPolicy) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        try:
            atomic_write(path, json.dumps(policy.raw, indent=2, ensure_ascii=False) + "\n", 0o640)
        except OSError as exc:
            LOG.warning("정책 캐시 저장 실패 %s: %s", path, exc)

    @staticmethod
    def _stage_of(exc: BaseException) -> str:
        from .errors import BaselineViolation, EnvelopeError, PolicyError, RenderError

        if isinstance(exc, EnvelopeError):
            return "envelope"
        if isinstance(exc, BaselineViolation):
            return "baseline"
        if isinstance(exc, PolicyError):
            return "policy"
        if isinstance(exc, RenderError):
            return "render"
        if isinstance(exc, PrecheckError):
            return "precheck"
        if isinstance(exc, VerifyFailed):
            return "verify"
        if isinstance(exc, ApplyError):
            return "apply"
        if isinstance(exc, StateError):
            return "state"
        return "error"
