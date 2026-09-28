"""적용 파이프라인 통합 테스트.

실제 커널이나 root 없이 전체 흐름을 검증한다.
  - 사전검사 실패 시 파일이 하나도 쓰이지 않는지
  - 적용 실패 시 스냅샷으로 되돌아가는지
  - 검증 실패 시 즉시 되돌아가는지
  - 자동 복구 예약이 적용 '전에' 걸리는지
  - confirm 전까지 pending 상태가 유지되고, 새 정책이 거부되는지
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from router.controller import NetworkController
from router.dynamic import DynamicElement, DynamicStore
from router.paths import NETPLAN_FILE, NFT_INET_FILE
from router.state import StateStore
from router.util import CommandResult, RecordingRunner
from router.verify import NetworkProbes

HEALTHY_ADDR = json.dumps([
    {"ifname": name, "operstate": "UP",
     "addr_info": [{"local": local, "prefixlen": 24}]}
    for name, local in (("vl-mgmt", "10.10.10.1"), ("vl-staff", "10.20.0.1"),
                        ("vl-guest", "10.30.0.1"), ("vl-quar", "10.99.0.1"))
] + [
    {"ifname": "ens18", "operstate": "UP",
     "addr_info": [{"local": "198.51.100.7", "prefixlen": 24}]},
    {"ifname": "ens19", "operstate": "UP",
     "addr_info": [{"local": "203.0.113.2", "prefixlen": 30}]},
])
HEALTHY_ROUTES = json.dumps([{"dst": "default", "dev": "ens18", "metric": 100}])
HEALTHY_NFT = ("table inet mooker {\n  chain input {}\n  chain forward {}\n"
               "  chain srcnat {}\n}")

BINARIES = {
    "nft", "netplan", "networkctl", "ip", "tc", "sysctl", "kea-dhcp4",
    "unbound-checkconf", "wg", "wg-quick", "systemctl", "systemd-run",
    "modprobe", "ping", "sh",
}


def healthy_responses(**overrides) -> dict[str, CommandResult]:
    base = {
        "addr show": CommandResult(("ip",), 0, HEALTHY_ADDR),
        "route show default": CommandResult(("ip",), 0, HEALTHY_ROUTES),
        "list table inet mooker": CommandResult(("nft",), 0, HEALTHY_NFT),
        "is-active": CommandResult(("systemctl",), 0, "active\n"),
        "ping": CommandResult(("ping",), 0, "2 received"),
    }
    base.update(overrides)
    return base


def healthy_probes(dns_ok: bool = True, https_ok: bool = True) -> NetworkProbes:
    """네트워크 프로브 대역. 실제 인터넷 없이 검증 로직을 시험한다."""
    return NetworkProbes(
        dns_query=lambda server, name, timeout: (dns_ok, f"{server}: answer 1개"),
        https_get=lambda url, timeout: (https_ok, "HTTP 200"),
        tcp_connect=lambda host, port, timeout: (True, f"{host}:{port} 연결됨"),
    )


@pytest.fixture
def env(tmp_path, trust, make_envelope, policy_doc):
    """격리된 파일시스템 루트와 컨트롤러 팩토리."""
    trust_store, _ = trust
    # 테스트에서는 안정화 대기가 의미 없다(가짜 러너는 즉시 응답한다).
    policy_doc["verify"]["settle_delay_s"] = 0
    policy_doc["verify"]["per_check_timeout_s"] = 1.0
    file_root = tmp_path / "root"
    file_root.mkdir()
    helper = tmp_path / "rollback"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)

    def build(responses: dict | None = None,
              probes: NetworkProbes | None = None) -> tuple[NetworkController, RecordingRunner]:
        runner = RecordingRunner(responses=responses or healthy_responses(),
                                 available=BINARIES)
        controller = NetworkController(
            runner,
            gateway_id=policy_doc["gateway_id"],
            trust=trust_store,
            state_store=StateStore(tmp_path / "state.json"),
            snapshot_root=str(tmp_path / "snapshots"),
            file_root=str(file_root),
            rollback_helper=str(helper),
            dynamic_store=DynamicStore(tmp_path / "dynamic.json"),
            lock_path=str(tmp_path / "apply.lock"),
            probes=probes or healthy_probes(),
        )
        return controller, runner

    return {"build": build, "root": file_root, "envelope": make_envelope(policy_doc),
            "doc": policy_doc, "tmp": tmp_path}


def _written(root: Path, path: str) -> str | None:
    candidate = root / path.lstrip("/")
    return candidate.read_text(encoding="utf-8") if candidate.exists() else None


# ---------------------------------------------------------------------------
def test_precheck_failure_changes_nothing(env):
    """사전검사가 실패하면 시스템은 손대지 않은 상태로 남아야 한다."""
    controller, runner = env["build"](healthy_responses(**{
        "-c -f": CommandResult(("nft",), 1, "", "syntax error near line 42"),
    }))
    report = controller.apply(env["envelope"])
    assert not report.ok and report.stage == "precheck"
    assert "시스템은 변경되지 않았다" in report.message
    assert _written(env["root"], NETPLAN_FILE) is None
    assert _written(env["root"], NFT_INET_FILE) is None
    # 스냅샷도 만들지 않았고, 복구 예약도 걸지 않았다.
    assert not any("systemd-run" in line for line in runner.argv_log())


def test_missing_binary_blocks_apply(env):
    controller, _ = env["build"]()
    controller.runner = RecordingRunner(responses=healthy_responses(),
                                        available=BINARIES - {"nft"})
    report = controller.apply(env["envelope"])
    assert not report.ok and report.stage == "precheck"
    assert "binary:nft" in report.message


def test_successful_apply_arms_guard_before_writing(env):
    """복구 예약이 적용보다 먼저 실행되어야 한다.

    순서가 뒤바뀌면 '적용 도중 접속이 끊기는' 바로 그 사고를 막지 못한다.
    """
    controller, runner = env["build"]()
    report = controller.apply(env["envelope"])
    assert report.ok, report.message
    assert report.stage == "pending-confirm"
    log = runner.argv_log()
    arm_index = next(i for i, line in enumerate(log) if "systemd-run" in line)
    apply_index = next(i for i, line in enumerate(log) if "netplan apply" in line)
    assert arm_index < apply_index

    assert "renderer: networkd" in _written(env["root"], NETPLAN_FILE)
    assert "table inet mooker" in _written(env["root"], NFT_INET_FILE)

    status = controller.status()
    assert status["applied_revision"] == 42
    assert status["confirmed_revision"] is None
    assert status["pending"]["revision"] == 42


def test_confirm_disarms_guard(env):
    controller, runner = env["build"]()
    assert controller.apply(env["envelope"]).stage == "pending-confirm"
    result = controller.confirm()
    assert result["ok"] and result["confirmed_revision"] == 42
    assert any("stop mooker-router-rollback" in line for line in runner.argv_log())
    status = controller.status()
    assert status["pending"] is None
    assert status["confirmed_revision"] == 42


def test_new_policy_rejected_while_pending(env, make_envelope):
    """확정 대기 중에 새 정책을 얹지 않는다.

    되돌림 지점이 두 개 겹치면 어디로 복구해야 하는지 알 수 없게 된다.
    """
    controller, _ = env["build"]()
    assert controller.apply(env["envelope"]).stage == "pending-confirm"
    document = json.loads(json.dumps(env["doc"]))
    document["revision"] = 43
    second = controller.apply(make_envelope(document))
    assert not second.ok and second.stage == "pending"
    assert "확정되지 않았다" in second.message


def test_apply_command_failure_rolls_back(env):
    """적용 명령이 실패하면 스냅샷으로 되돌리고 예약을 해제한다."""
    controller, runner = env["build"](healthy_responses(**{
        "netplan apply": CommandResult(("netplan", "apply"), 1, "", "링크가 존재하지 않는다"),
    }))
    report = controller.apply(env["envelope"])
    assert not report.ok and report.stage == "apply"
    assert report.rollback  # 복구가 수행되었다
    # 이전 상태에 파일이 없었으므로 복구는 파일 제거를 의미한다.
    assert _written(env["root"], NETPLAN_FILE) is None
    log = runner.argv_log()
    assert any("stop mooker-router-rollback" in line for line in log)
    assert controller.status()["pending"] is None


def test_verify_failure_rolls_back_immediately(env):
    """적용은 성공했지만 회선이 죽은 경우, 타이머를 기다리지 않고 즉시 복구한다."""
    controller, runner = env["build"](healthy_responses(**{
        "addr show": CommandResult(("ip",), 0, json.dumps([
            {"ifname": "vl-mgmt", "operstate": "DOWN", "addr_info": []},
        ])),
    }))
    report = controller.apply(env["envelope"])
    assert not report.ok and report.stage == "verify"
    assert "즉시 되돌린다" in report.message
    assert report.verify["ok"] is False
    assert _written(env["root"], NETPLAN_FILE) is None


def test_rollback_restores_previous_content(env, make_envelope):
    """두 번째 정책을 되돌리면 첫 번째 정책의 파일 내용으로 돌아가야 한다."""
    controller, _ = env["build"]()
    controller.apply(env["envelope"])
    controller.confirm()
    first_netplan = _written(env["root"], NETPLAN_FILE)

    document = json.loads(json.dumps(env["doc"]))
    document["revision"] = 43
    document["wan_links"][1]["metric"] = 250      # 보조 회선 우선순위 변경
    controller, _ = env["build"]()
    report = controller.apply(make_envelope(document))
    assert report.ok, report.message
    assert "metric: 250" in _written(env["root"], NETPLAN_FILE)

    result = controller.rollback(reason="테스트")
    assert result["ok"], result
    assert _written(env["root"], NETPLAN_FILE) == first_netplan
    assert "metric: 250" not in _written(env["root"], NETPLAN_FILE)
    assert controller.status()["applied_revision"] == 42


def test_stale_pending_is_reconciled(env):
    """타이머가 이미 발동한 뒤 남은 pending 때문에 영구히 막히지 않아야 한다."""
    controller, _ = env["build"]()
    controller.apply(env["envelope"])
    state = controller.state_store.load()
    state.pending.deadline_epoch = 0  # 만료시킨다
    controller.state_store.save(state)

    status = controller.status()
    assert status["pending"] is None
    assert "자동 복구" in status["last_error"]
    # 이제 새 적용이 가능하다
    assert controller.apply(env["envelope"], force=True).ok


def test_no_change_apply_is_idempotent(env):
    controller, _ = env["build"]()
    assert controller.apply(env["envelope"]).ok
    controller.confirm()
    second = controller.apply(env["envelope"], force=True)
    assert second.ok and second.stage == "no-change"


def test_dry_run_touches_nothing(env):
    controller, runner = env["build"]()
    report = controller.apply(env["envelope"], dry_run=True)
    assert report.ok and report.stage == "dry-run"
    assert _written(env["root"], NETPLAN_FILE) is None
    assert not any("netplan apply" in line for line in runner.argv_log())


def test_dynamic_elements_survive_policy_reapply(env):
    """정책 재적용으로 nft 테이블이 교체돼도 격리 원소가 되살아나야 한다."""
    controller, runner = env["build"]()
    controller.dynamic_store.upsert(
        DynamicElement("mac", "AA:BB:CC:DD:EE:99", reason="c2", expires_at=None))
    controller.apply(env["envelope"])
    # 적용 후 flush+add로 셋을 다시 채운 흔적이 있어야 한다.
    element_pushes = [stdin for argv, stdin in runner.calls
                      if argv[:2] == ("nft", "-f") and stdin and "add element" in stdin]
    assert any("AA:BB:CC:DD:EE:99" in stdin for stdin in element_pushes)
    assert any("bridge mooker_l2 quarantine_mac" in stdin for stdin in element_pushes)


def test_stale_dropin_is_removed(env, make_envelope):
    """정책에서 VLAN을 지우면 남은 드롭인 파일도 제거되어야 한다."""
    controller, _ = env["build"]()
    controller.apply(env["envelope"])
    controller.confirm()
    dropin = env["root"] / "etc/systemd/network/10-netplan-ens21.network.d/50-mooker-l2.conf"
    assert dropin.exists()

    document = json.loads(json.dumps(env["doc"]))
    document["revision"] = 43
    document["bridges"][0]["ports"] = ["ens20", "ens22"]
    document["lans"][1]["untagged_ports"] = []
    controller, _ = env["build"]()
    assert controller.apply(make_envelope(document)).ok
    assert not dropin.exists()


def test_manual_mode_waits_for_operator(env, make_envelope):
    """manual 모드: 검증을 통과해도 사람이 confirm할 때까지 예약이 유지된다.

    SSH로 원격 작업할 때 필요한 모드다. 접속이 끊기면 confirm을 못 하므로
    타이머가 장비를 되돌린다 — 그것이 이 모드의 목적이다.
    """
    document = json.loads(json.dumps(env["doc"]))
    document["commit_confirm"] = {"mode": "manual", "timeout_s": 120}
    document["verify"]["require_control_plane"] = False
    document["verify"]["control_plane_url"] = ""
    controller, runner = env["build"]()
    report = controller.apply(make_envelope(document))
    assert report.ok and report.stage == "pending-confirm"
    assert "운영자 confirm" in report.message
    status = controller.status()
    assert status["pending"]["confirm_mode"] == "manual"
    # 예약은 아직 살아 있다 (해제 명령이 나가지 않았다)
    assert not any("stop mooker-router-rollback" in line for line in runner.argv_log())

    assert controller.confirm()["ok"]
    assert controller.status()["pending"] is None


def test_none_mode_confirms_immediately(env, make_envelope):
    document = json.loads(json.dumps(env["doc"]))
    document["commit_confirm"] = {"mode": "none", "timeout_s": 60}
    document["verify"]["require_control_plane"] = False
    document["verify"]["control_plane_url"] = ""
    controller, runner = env["build"]()
    report = controller.apply(make_envelope(document))
    assert report.ok and report.stage == "confirmed"
    assert controller.status()["confirmed_revision"] == 42
    assert any("stop mooker-router-rollback" in line for line in runner.argv_log())
