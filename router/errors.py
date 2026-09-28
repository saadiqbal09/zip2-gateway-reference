"""Router Plane 예외 계층.

호출자는 예외 종류로 '어느 단계에서 멈췄는가'를 구분한다. 적용 단계 이전
(Envelope/Policy/Render/Precheck)에서 발생한 예외는 시스템을 전혀 건드리지
않았음을 보장한다.
"""
from __future__ import annotations


class RouterError(Exception):
    """모든 Router Plane 오류의 기반."""

    exit_code = 1


class EnvelopeError(RouterError):
    """서명 봉투가 유효하지 않다(서명 불일치, 키 미신뢰, 만료, 대상 불일치)."""

    exit_code = 10


class PolicyError(RouterError):
    """정책 스키마 또는 의미 검증 실패."""

    exit_code = 11

    def __init__(self, message: str, path: str = ""):
        self.path = path
        super().__init__(f"{path}: {message}" if path else message)


class BaselineViolation(PolicyError):
    """하위 정책이 완화할 수 없는 보안 baseline을 침해했다."""

    exit_code = 12


class RenderError(RouterError):
    """정책을 설정 파일/명령으로 컴파일하지 못했다."""

    exit_code = 13


class PrecheckError(RouterError):
    """사전검사 실패. 시스템은 변경되지 않았다."""

    exit_code = 14

    def __init__(self, message: str, report=None):
        self.report = report
        super().__init__(message)


class ApplyError(RouterError):
    """적용 중 실패. 스냅샷 복구가 시도되었거나 예약되어 있다."""

    exit_code = 15


class VerifyFailed(RouterError):
    """적용은 되었으나 연결 검증 실패. 즉시 rollback 대상."""

    exit_code = 16

    def __init__(self, message: str, report=None):
        self.report = report
        super().__init__(message)


class RollbackError(RouterError):
    """복구 자체가 실패했다. 사람이 콘솔로 개입해야 한다."""

    exit_code = 17


class StateError(RouterError):
    """로컬 상태 파일이 손상되었거나 요청과 모순된다."""

    exit_code = 18
