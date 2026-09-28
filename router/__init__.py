"""Mooker Gateway Router Plane.

Ubuntu 24.04 LTS 소프트웨어 라우터의 제어 계층이다. 중앙에서 서명된 선언형
네트워크 정책(desired state)을 받아 다음 순서로만 시스템을 변경한다.

    서명 검증 -> 스키마/베이스라인 검증 -> 렌더링 -> 사전검사(staging)
    -> 스냅샷 -> 자동 rollback 예약(commit-confirm) -> 적용 -> 연결 검증
    -> confirm 또는 자동 복구

Agent가 ip/nft/tc 명령을 즉흥적으로 실행하지 않는다는 것이 이 패키지의 계약이다.
모든 변경은 RenderPlan(파일 + 명령 + 서비스 액션)으로 표현되고, 사전검사를
통과한 계획만 적용된다.
"""

__all__ = ["__version__"]
__version__ = "0.2.0"
