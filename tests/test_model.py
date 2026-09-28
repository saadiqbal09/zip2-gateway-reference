"""정책 검증 테스트.

여기서 잡아야 하는 것은 "문법은 맞지만 적용하면 현장이 죽는 정책"이다. 서브넷
겹침, DHCP pool과 Gateway 주소 충돌, 관리 접근 대역 소실 같은 것들이다.
"""
from __future__ import annotations

import copy

import pytest

from router.errors import BaselineViolation, PolicyError
from router.model import RouterPolicy


def test_sample_policy_parses(policy):
    assert policy.revision == 42
    assert [link.name for link in policy.wan_links] == ["wan1", "wan2"]
    assert policy.lan("staff").gateway_ipv4 == "10.20.0.1"
    assert policy.wan("wan2").table == 200
    assert len(policy.dhcp_segments) == 4


def test_pppoe_link_interface_differs(policy_doc):
    policy_doc["wan_links"][0] = {
        "name": "wan1", "interface": "ens18", "mode": "pppoe", "metric": 100,
        "pppoe": {"username": "user@isp", "password_ref": "wan1-pppoe"},
    }
    policy = RouterPolicy.parse(policy_doc)
    # PPPoE는 L3가 ppp 디바이스에 올라온다. 방화벽/NAT는 이 이름을 써야 한다.
    assert policy.wan("wan1").link_interface == "ppp-wan1"


@pytest.mark.parametrize("mutate, expected", [
    # 서브넷이 겹치면 라우팅이 비결정적이 된다(guest를 staff의 상위 대역으로 만든다).
    (lambda d: (d["lans"][2].update({"addresses": ["10.20.1.1/16"]}),
                d["lans"][2]["dhcp"].update({"subnet": "10.20.0.0/16",
                                             "pool_start": "10.20.200.1",
                                             "pool_end": "10.20.200.254"})), "겹친다"),
    # Gateway 주소가 DHCP pool 안에 있으면 주소 충돌이 난다.
    (lambda d: d["lans"][2]["dhcp"].update({"pool_start": "10.30.0.1"}), "pool 안에 있다"),
    # reservation이 동적 pool과 겹치면 Kea가 같은 주소를 두 번 내준다.
    (lambda d: d["lans"][1]["dhcp"]["reservations"][0].update({"ip": "10.20.0.150"}),
     "동적 pool과 겹친다"),
    # pool이 subnet 밖이면 아무도 주소를 못 받는다.
    (lambda d: d["lans"][1]["dhcp"].update({"pool_end": "10.99.0.9"}), "subnet 밖"),
    # 다회선인데 metric이 같으면 failover 판정이 불가능하다.
    (lambda d: d["wan_links"][1].update({"metric": 100}), "서로 다른 metric"),
    # 브리지가 WAN 인터페이스를 삼키면 회선이 사라진다.
    (lambda d: d["bridges"][0].update({"ports": ["ens18", "ens20", "ens21", "ens22"]}),
     "WAN 인터페이스와 겹친다"),
    # 정의되지 않은 zone 참조
    (lambda d: d["lans"][0].update({"zone": "nowhere"}), "firewall.zones에 없다"),
    # 같은 상위 링크에 VLAN 중복
    (lambda d: d["lans"][2].update({"vlan_id": 20}), "중복 정의"),
    # 한 포트를 두 VLAN의 untagged로 지정
    (lambda d: d["lans"][2].update({"untagged_ports": ["ens21"]}), "동시에 untagged"),
    # port_forward 대상이 어떤 LAN에도 없다
    (lambda d: d["firewall"]["port_forwards"][0].update({"to_address": "203.0.113.9"}),
     "LAN 서브넷에도 없다"),
    # 알 수 없는 필드는 조용히 무시하지 않는다
    (lambda d: d.update({"unknown_feature": True}), "알 수 없는 항목"),
])
def test_invalid_policies_rejected(policy_doc, mutate, expected):
    mutate(policy_doc)
    with pytest.raises(PolicyError) as info:
        RouterPolicy.parse(policy_doc)
    assert expected in str(info.value)


@pytest.mark.parametrize("mutate, expected", [
    # 관리 접근 대역이 없으면 적용 후 아무도 접속할 수 없다.
    (lambda d: d["firewall"].update({"mgmt_allow_cidrs": []}), "관리 접근 경로가 사라진다"),
    # 전체 대역 개방은 관리 접근의 의미를 없앤다.
    (lambda d: d["firewall"].update({"mgmt_allow_cidrs": ["0.0.0.0/0"]}), "전체 대역"),
    # WAN에서 Gateway로의 서비스 개방 금지 (아키텍처 원칙)
    (lambda d: d["firewall"]["service_allows"].append(
        {"zone": "wan", "protocol": "tcp", "ports": [22]}), "WAN zone에서 Gateway로"),
    # 중앙 confirm을 요구하면서 제어 채널 검증을 끌 수 없다
    (lambda d: d["verify"].update({"require_control_plane": False}), "제어 채널 검증"),
    # 관리 터널 allowed_ips 전체 개방 금지
    (lambda d: d["mgmt_tunnel"].update({"enabled": True, "allowed_ips": ["0.0.0.0/0"]}),
     "0.0.0.0/0"),
])
def test_baseline_cannot_be_relaxed(policy_doc, mutate, expected):
    mutate(policy_doc)
    with pytest.raises(BaselineViolation) as info:
        RouterPolicy.parse(policy_doc)
    assert expected in str(info.value)


def test_secrets_never_in_policy(policy_doc):
    """정책 문서에 평문 비밀값을 넣을 자리가 없어야 한다."""
    policy_doc["wan_links"][0] = {
        "name": "wan1", "interface": "ens18", "mode": "pppoe", "metric": 100,
        "pppoe": {"username": "u", "password_ref": "wan1-pppoe",
                   "password": "plaintext-secret"},
    }
    with pytest.raises(PolicyError) as info:
        RouterPolicy.parse(policy_doc)
    # password 같은 평문 비밀 필드는 스키마에 존재하지 않으므로 거부된다.
    assert "알 수 없는 항목" in str(info.value) and "password" in str(info.value)


# ---------------------------------------------------------------------------
# commit-confirm 모드
# ---------------------------------------------------------------------------
def test_commit_confirm_legacy_bool_still_works(policy_doc):
    """구 스키마(require_central_confirm)를 계속 받아들인다."""
    policy_doc["commit_confirm"] = {"timeout_s": 300, "require_central_confirm": True}
    assert RouterPolicy.parse(policy_doc).commit_confirm.mode == "central"
    policy_doc["commit_confirm"] = {"timeout_s": 300, "require_central_confirm": False}
    policy_doc["verify"]["require_control_plane"] = False
    policy_doc["verify"]["control_plane_url"] = ""
    assert RouterPolicy.parse(policy_doc).commit_confirm.mode == "none"


def test_manual_mode_does_not_require_control_plane(policy_doc):
    """중앙 플랫폼이 없는 랩/개발 장비에서 사람이 확정하는 모드."""
    policy_doc["commit_confirm"] = {"mode": "manual", "timeout_s": 120}
    policy_doc["verify"]["require_control_plane"] = False
    policy_doc["verify"]["control_plane_url"] = ""
    policy = RouterPolicy.parse(policy_doc)
    assert policy.commit_confirm.mode == "manual"
    assert policy.commit_confirm.requires_confirm is True
    assert policy.commit_confirm.require_central_confirm is False


def test_central_mode_still_requires_control_plane(policy_doc):
    policy_doc["commit_confirm"] = {"mode": "central", "timeout_s": 300}
    policy_doc["verify"]["require_control_plane"] = False
    with pytest.raises(BaselineViolation) as info:
        RouterPolicy.parse(policy_doc)
    assert "manual" in str(info.value)


def test_none_mode_auto_confirms(policy_doc):
    policy_doc["commit_confirm"] = {"mode": "none", "timeout_s": 60}
    policy_doc["verify"]["require_control_plane"] = False
    policy_doc["verify"]["control_plane_url"] = ""
    policy = RouterPolicy.parse(policy_doc)
    assert policy.commit_confirm.requires_confirm is False
