"""검증 계층 테스트.

DNS 질의는 외부 도구(dig) 없이 직접 만든다. 그 패킷이 실제로 올바른지 확인하지
않으면, 검증이 항상 실패하거나 항상 성공하는 쪽으로 조용히 망가질 수 있다.
"""
from __future__ import annotations

import json
import socket
import struct
import threading

from router.model import RouterPolicy
from router.util import CommandResult, RecordingRunner
from router.verify import _dns_query, verify


def _fake_dns_server(answers: int = 1, rcode: int = 0):
    """단일 질의에 응답하는 최소 DNS 서버. 실제 패킷 왕복을 검증한다."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def serve():
        data, addr = sock.recvfrom(2048)
        transaction_id = data[:2]
        question = data[12:]
        flags = struct.pack(">H", 0x8180 | rcode)
        header = transaction_id + flags + struct.pack(">HHHH", 1, answers, 0, 0)
        answer = b""
        if answers:
            answer = (b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
                      + socket.inet_aton("203.0.113.10"))
        sock.sendto(header + question + answer, addr)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_dns_query_parses_valid_answer():
    port = _fake_dns_server(answers=1)
    ok, detail = _dns_query("127.0.0.1", "www.example.com", 3.0, port=port)
    assert ok, detail
    assert "answer 1개" in detail


def test_dns_query_reports_nxdomain():
    port = _fake_dns_server(answers=0, rcode=3)
    ok, detail = _dns_query("127.0.0.1", "blocked.example.test", 3.0, port=port)
    assert not ok
    assert "rcode=3" in detail


def test_dns_query_timeout_is_not_a_crash():
    ok, detail = _dns_query("127.0.0.1", "www.example.com", 0.3, port=1)
    assert not ok and detail


def test_verify_flags_missing_address(policy_doc):
    """인터페이스가 올라왔지만 주소가 없는 상태를 잡아야 한다.

    netplan apply가 성공을 반환하고도 이런 상태가 되는 경우가 실제로 있다.
    """
    policy_doc["verify"]["settle_delay_s"] = 0
    policy = RouterPolicy.parse(policy_doc)
    runner = RecordingRunner(responses={
        "addr show": CommandResult(("ip",), 0, json.dumps([
            {"ifname": "vl-staff", "operstate": "UP", "addr_info": []},
        ])),
        "route show default": CommandResult(("ip",), 0, "[]"),
        "list table inet mooker": CommandResult(("nft",), 1, "", "no such table"),
        "is-active": CommandResult(("systemctl",), 0, "inactive\n"),
    })
    report = verify(policy, runner, skip_delay=True)
    assert not report.ok
    names = {check.name for check in report.failures()}
    assert "interface:vl-staff" in names
    assert "nftables:inet mooker" in names
    assert "route:default" in names


def test_verify_treats_optional_wan_as_soft(policy_doc):
    """required_for_online=false 회선의 실패로 전체 적용을 되돌리지 않는다."""
    policy_doc["verify"]["settle_delay_s"] = 0
    policy = RouterPolicy.parse(policy_doc)
    addr = json.dumps([
        {"ifname": name, "operstate": "UP", "addr_info": [{"local": ip, "prefixlen": 24}]}
        for name, ip in (("vl-mgmt", "10.10.10.1"), ("vl-staff", "10.20.0.1"),
                         ("vl-guest", "10.30.0.1"), ("vl-quar", "10.99.0.1"),
                         ("ens18", "198.51.100.7"))
    ])
    runner = RecordingRunner(responses={
        "addr show": CommandResult(("ip",), 0, addr),
        "route show default": CommandResult(("ip",), 0,
                                            json.dumps([{"dev": "ens18"}])),
        "list table inet mooker": CommandResult(
            ("nft",), 0, "chain input {} chain forward {} chain srcnat {}"),
        "is-active": CommandResult(("systemctl",), 0, "active\n"),
        "ping": CommandResult(("ping",), 0, "2 received"),
    })
    from router.verify import NetworkProbes
    probes = NetworkProbes(
        dns_query=lambda s, n, t: (True, "ok"),
        https_get=lambda u, t: (True, "HTTP 200"),
        tcp_connect=lambda h, p, t: (True, "ok"),
    )
    report = verify(policy, runner, skip_delay=True, probes=probes)
    # ens19(wan2)는 링크 자체가 없지만 required_for_online=false 이므로 soft다.
    soft_failures = [c for c in report.checks if not c.ok and c.severity == "soft"]
    assert any(c.name.startswith("wan:wan2:") for c in soft_failures)
    assert report.ok
