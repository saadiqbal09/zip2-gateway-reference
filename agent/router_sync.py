"""Agent ↔ Router Plane 연결.

Agent는 네트워크 명령을 직접 실행하지 않는다. 중앙에서 받은 서명된 정책 봉투를
NetworkController에 넘기고, 결과를 보고하는 일만 한다.

commit-confirm의 '중앙 confirm'을 무엇으로 볼 것인가가 이 모듈의 핵심 판단이다.
답은 "적용 후에도 중앙과 통신이 되는가"다. 관리 경로가 살아 있다는 사실 자체가
가장 정확한 확인이며, 별도 승인 절차를 기다리는 동안 회선이 끊겨 있는 상황을
구분해 주지 못하는 다른 방법보다 낫다. 그래서 적용 성공 후 새 heartbeat를
보내고, 중앙이 응답하면 confirm한다. 응답이 없으면 confirm하지 않고, 예약된
타이머가 장비를 원상 복구한다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from router.controller import ApplyReport, NetworkController
from router.dynamic import DynamicStore, from_central_payload, sync as sync_dynamic
from router.envelope import TrustStore
from router.errors import RouterError
from router.paths import TRUST_DIR
from router.util import LOG, SubprocessRunner

NETWORK_POLICY_PATH = "/api/v1/gateway/network-policy"
NETWORK_POLICY_ACK_PATH = "/api/v1/gateway/network-policy/ack"


@dataclass
class SyncOutcome:
    changed: bool = False
    stage: str = "idle"
    message: str = ""
    revision: int | None = None
    confirmed: bool = False
    report: dict[str, Any] | None = None

    def to_health(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "revision": self.revision,
            "confirmed": self.confirmed,
            "message": self.message[:500],
        }


class RouterPlaneSync:
    def __init__(self, gateway_id: str | None, *, allow_hmac: bool = False,
                 trust_dir: str = TRUST_DIR, enabled: bool = True):
        self.enabled = enabled
        self.gateway_id = gateway_id
        self.controller = NetworkController(
            SubprocessRunner(),
            gateway_id=gateway_id,
            trust=TrustStore(trust_dir, allow_hmac=allow_hmac),
        )
        self.dynamic_store = DynamicStore()
        self._unsupported_logged = False

    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        try:
            status = self.controller.status()
        except RouterError as exc:
            return {"enabled": True, "error": str(exc)}
        return {"enabled": True, **status}

    def sync(self, fetch: Callable[[str], dict[str, Any] | None],
             heartbeat: Callable[[], dict[str, Any] | None],
             ack: Callable[[dict[str, Any]], None] | None = None) -> SyncOutcome:
        """정책을 받아 적용하고, 필요하면 confirm까지 수행한다.

        ``fetch``는 경로를 받아 JSON을 돌려주는 함수다(Agent의 서명된 요청 함수).
        엔드포인트가 없으면 None을 돌려주도록 한다 — Router Plane 미지원 백엔드와
        같은 Agent 바이너리를 쓸 수 있어야 한다.
        """
        if not self.enabled:
            return SyncOutcome(stage="disabled")

        # 확정 대기 중인 적용이 있으면, 새 정책을 받기 전에 그것을 마무리한다.
        pending = self._resolve_pending(heartbeat)
        if pending is not None:
            self._report(ack, pending)
            return pending

        try:
            envelope = fetch(NETWORK_POLICY_PATH)
        except Exception as exc:  # 통신 실패는 다음 주기에 재시도한다
            return SyncOutcome(stage="fetch-failed", message=str(exc))
        if envelope is None:
            if not self._unsupported_logged:
                LOG.info("중앙에 네트워크 정책 엔드포인트가 없다. Router Plane 동기화를 건너뛴다.")
                self._unsupported_logged = True
            return SyncOutcome(stage="unsupported")

        # 격리/차단 목록은 정책과 별개로 즉시 반영한다(초 단위 운영 판단).
        self._sync_dynamic(envelope)

        if not envelope.get("policy"):
            return SyncOutcome(stage="no-policy")

        state = self.controller.status()
        incoming = envelope.get("policy", {}).get("revision")
        if isinstance(incoming, int) and incoming == state.get("confirmed_revision"):
            return SyncOutcome(stage="up-to-date", revision=incoming)

        # 봉투는 서명 대상만 담아 넘긴다. 중앙 응답에는 enforcement 같은
        # 서명 대상 밖의 필드가 함께 오므로, 그대로 넘기면 봉투 검증이 거부한다.
        signed = {key: envelope[key] for key in
                  ("policy", "signature", "not_before", "not_after") if key in envelope}
        report = self.controller.apply(signed, reason="central policy sync")
        outcome = SyncOutcome(
            changed=report.ok and report.stage not in {"no-change", "dry-run"},
            stage=report.stage,
            message=report.message,
            revision=report.revision,
            report=report.to_dict(),
        )
        if report.stage == "pending-confirm" and \
                self.controller.status().get("pending", {}).get("confirm_mode") == "manual":
            outcome.stage = "pending-confirm"
        elif report.stage == "pending-confirm":
            confirmed = self._confirm_via_control_channel(report, heartbeat)
            outcome.confirmed = confirmed
            outcome.stage = "confirmed" if confirmed else "pending-confirm"
        elif report.stage == "confirmed":
            outcome.confirmed = True
        if not report.ok:
            LOG.error("정책 적용 실패 [%s]: %s", report.stage, report.message.splitlines()[0])
        self._report(ack, outcome)
        return outcome

    def _report(self, ack: Callable[[dict[str, Any]], None] | None,
                outcome: SyncOutcome) -> None:
        """적용 결과를 중앙에 보고한다.

        실패한 적용도 반드시 보고한다. 운영 화면에서 'desired는 42인데 applied는
        41'이라는 사실이 보여야 담당자가 개입할 수 있다. 보고 실패는 다음 주기에
        재시도되므로 여기서 예외를 올리지 않는다.
        """
        if ack is None or outcome.stage in {"idle", "disabled", "unsupported", "up-to-date"}:
            return
        status = self.controller.status()
        try:
            ack({
                "desired_revision": status.get("desired_revision"),
                "applied_revision": status.get("applied_revision"),
                "confirmed_revision": status.get("confirmed_revision"),
                "stage": outcome.stage[:32],
                "ok": outcome.confirmed or outcome.stage in {"confirmed", "no-change"},
                "detail": {
                    "message": outcome.message[:1000],
                    "revision": outcome.revision,
                    "verify": (outcome.report or {}).get("verify", {}),
                    "rollback": (outcome.report or {}).get("rollback", {}),
                    "last_error": status.get("last_error"),
                },
            })
        except Exception as exc:
            LOG.warning("적용 결과 보고 실패(다음 주기에 재시도): %s", exc)

    # ------------------------------------------------------------------
    def _sync_dynamic(self, envelope: dict[str, Any]) -> None:
        payload = envelope.get("enforcement") or {}
        if not payload:
            return
        elements = from_central_payload(payload)
        current = {(item.kind, item.value) for item in self.dynamic_store.load()}
        incoming = {(item.kind, item.value) for item in elements}
        self.dynamic_store.replace(elements)
        if current != incoming:
            result = sync_dynamic(self.controller.runner, self.dynamic_store)
            LOG.info("격리/차단 목록 갱신: %d개 (ok=%s)", result["total"], result["ok"])

    def _resolve_pending(self, heartbeat: Callable[[], dict[str, Any] | None]) -> SyncOutcome | None:
        status = self.controller.status()
        pending = status.get("pending")
        if not pending:
            return None
        if pending.get("confirm_mode") == "manual":
            # 사람이 확정해야 하는 적용이다. Agent가 대신 confirm하면 그 모드를
            # 선택한 의미가 사라진다(원격 작업 중 접속 상실을 사람이 판단해야 한다).
            LOG.info("revision %s는 운영자 confirm 대기 중이다. Agent는 개입하지 않는다.",
                     pending["revision"])
            return SyncOutcome(stage="pending-confirm", revision=pending["revision"],
                               message="운영자 confirm 대기 (mooker-router confirm)")
        # 관리 경로가 살아 있다는 증거가 곧 confirm이다.
        if heartbeat() is not None:
            result = self.controller.confirm(pending["revision"])
            LOG.warning("확정 대기 중이던 revision %s를 confirm했다 (ok=%s)",
                        pending["revision"], result["ok"])
            return SyncOutcome(changed=True, stage="confirmed" if result["ok"] else "confirm-failed",
                               message=result["message"], revision=pending["revision"],
                               confirmed=result["ok"])
        LOG.error("확정 대기 중인 revision %s: 중앙에 도달할 수 없다. "
                  "남은 시간 %.0fs 후 자동 복구된다.",
                  pending["revision"], pending.get("seconds_left", 0))
        return SyncOutcome(stage="pending-confirm", revision=pending["revision"],
                           message="중앙 도달 실패 — 자동 복구 예정")

    def _confirm_via_control_channel(self, report: ApplyReport,
                                     heartbeat: Callable[[], dict[str, Any] | None]) -> bool:
        """적용 직후 새 heartbeat로 관리 경로 생존을 확인한다."""
        for attempt in range(3):
            if heartbeat() is not None:
                result = self.controller.confirm(report.revision)
                if result["ok"]:
                    LOG.info("revision %s 확정 (제어 채널 생존 확인)", report.revision)
                    return True
                LOG.error("confirm 실패: %s", result["message"])
                return False
            LOG.warning("적용 후 중앙 도달 실패 (시도 %d/3). 재시도한다.", attempt + 1)
            time.sleep(3)
        LOG.critical("적용 후 중앙에 도달할 수 없다. confirm하지 않는다 — "
                     "예약된 자동 복구가 장비를 되돌린다.")
        return False
