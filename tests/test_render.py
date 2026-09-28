"""렌더러 테스트.

검증 대상은 "설정 파일이 만들어졌는가"가 아니라 "그 내용이 의도한 보안·동작
성질을 갖는가"다. 예: 격리 규칙이 ct established보다 앞에 있는지, NAT가 PPPoE
디바이스를 가리키는지, 비밀값이 파일 밖으로 새지 않는지.
"""
from __future__ import annotations

import json

import pytest

from router.errors import RenderError
from router.model import RouterPolicy
from router.paths import (
    KEA_DHCP4_FILE,
    NETPLAN_FILE,
    NFT_BRIDGE_FILE,
    NFT_INET_FILE,
    UNBOUND_CONF_FILE,
)
from router.render import render_all
from router.render import nftables as nft_render
from router.render import pppoe as pppoe_render
from router.render import wireguard as wg_render


def _file(plan, path):
    for target in plan.files:
        if target.path == path:
            return target
    raise AssertionError(f"{path}가 계획에 없다. 있는 것: {plan.file_paths()}")


def test_render_is_deterministic(policy, ctx):
    first = render_all(policy, ctx)
    second = render_all(policy, ctx)
    assert {t.path: t.content for t in first.files} == {t.path: t.content for t in second.files}


def test_netplan_structure(policy, ctx):
    content = _file(render_all(policy, ctx), NETPLAN_FILE).content
    assert "renderer: networkd" in content
    # WAN1은 DHCP + metric, ISP DNS는 시스템에 주입하지 않는다.
    assert "route-metric: 100" in content and "use-dns: false" in content
    # WAN2는 static + 정책 라우팅 테이블
    assert "table: 200" in content and "from: 203.0.113.2" in content
    # VLAN 디바이스와 브리지
    assert "vl-staff:" in content and "id: 20" in content and "link: br-lan" in content
    # 브리지 포트에는 L3를 올리지 않는다
    assert "link-local: []" in content
    # netplan 파일은 비밀을 담을 수 있으므로 0600
    assert _file(render_all(policy, ctx), NETPLAN_FILE).mode == 0o600


def test_nftables_quarantine_precedes_established(policy, ctx):
    """격리는 기존 세션보다 먼저 판정되어야 즉시 효력이 있다."""
    content = _file(render_all(policy, ctx), NFT_INET_FILE).content
    input_chain = content.split("chain input {")[1].split("chain forward {")[0]
    quarantine_at = input_chain.index("@quarantine_mac")
    established_at = input_chain.index("ct state established,related")
    assert quarantine_at < established_at


def test_nftables_forward_and_input_gates_differ(policy, ctx):
    """input 게이트는 DHCP/DNS를 허용하지만 forward 게이트는 전부 막아야 한다.

    하나의 체인을 공유하면 격리 단말이 외부 DNS로 나가는 경로가 열린다.
    """
    content = _file(render_all(policy, ctx), NFT_INET_FILE).content
    # 체인 종료는 4칸 들여쓴 닫는 괄호다. 셋 리터럴의 '}'와 구분해야 한다.
    input_gate = content.split("chain quarantine_input {")[1].split("\n    }")[0]
    forward_gate = content.split("chain quarantine_forward {")[1].split("\n    }")[0]
    assert "dport 53" in input_gate
    assert "accept" not in forward_gate
    assert "drop" in forward_gate


def test_nftables_output_stays_accept(policy, ctx):
    """잘못된 정책이 중앙 제어 채널을 스스로 끊지 못하게 한다."""
    content = _file(render_all(policy, ctx), NFT_INET_FILE).content
    output_chain = content.split("chain output {")[1].split("chain dstnat {")[0]
    assert "policy accept;" in output_chain


def test_nftables_never_flushes_whole_ruleset(policy, ctx):
    """고객이 쓰는 다른 테이블을 지우지 않는다."""
    plan = render_all(policy, ctx)
    for path in (NFT_INET_FILE, NFT_BRIDGE_FILE):
        content = _file(plan, path).content
        assert "flush ruleset" not in content
        assert "delete table inet mooker\n" in content or \
               "delete table bridge mooker_l2\n" in content


def test_nftables_explicit_rules_precede_zone_matrix(policy, ctx):
    """명시 drop 규칙이 넓은 zone 허용보다 앞에 와야 의미가 있다."""
    content = _file(render_all(policy, ctx), NFT_INET_FILE).content
    forward = content.split("chain forward {")[1].split("chain output {")[0]
    assert forward.index('"guest-no-private"') < forward.index('"guest->wan"')


def test_nftables_nat_uses_ppp_device_for_pppoe(policy_doc, ctx):
    policy_doc["wan_links"][0] = {
        "name": "wan1", "interface": "ens18", "mode": "pppoe", "metric": 100,
        "pppoe": {"username": "user@isp", "password_ref": "wan1-pppoe"},
    }
    policy = RouterPolicy.parse(policy_doc)
    content = nft_render.render(policy, ctx).files[0].content
    assert 'oifname "ppp-wan1" counter masquerade' in content
    assert 'oifname "ens18" counter masquerade' not in content


def test_nftables_mss_clamp_present_for_pppoe(policy, ctx):
    content = _file(render_all(policy, ctx), NFT_INET_FILE).content
    assert "tcp option maxseg size set rt mtu" in content


def test_kea_config_is_valid_json_with_reservations(policy, ctx):
    content = _file(render_all(policy, ctx), KEA_DHCP4_FILE).content
    body = "\n".join(line for line in content.splitlines() if not line.startswith("//"))
    document = json.loads(body)
    subnets = document["Dhcp4"]["subnet4"]
    assert len(subnets) == 4
    staff = next(s for s in subnets if s["subnet"] == "10.20.0.0/24")
    assert staff["interface"] == "vl-staff"
    assert {r["ip-address"] for r in staff["reservations"]} == {"10.20.0.50", "10.20.0.51"}
    assert staff["reservations-out-of-pool"] is True
    # option-data의 router/DNS는 세그먼트 Gateway 주소로 자동 채워진다
    routers = next(o for o in staff["option-data"] if o["name"] == "routers")
    assert routers["data"] == "10.20.0.1"


def test_kea_known_class_when_unknown_clients_denied(policy_doc, ctx):
    policy_doc["lans"][1]["dhcp"]["unknown_clients_allowed"] = False
    policy = RouterPolicy.parse(policy_doc)
    plan = render_all(policy, ctx)
    body = "\n".join(line for line in _file(plan, KEA_DHCP4_FILE).content.splitlines()
                     if not line.startswith("//"))
    staff = next(s for s in json.loads(body)["Dhcp4"]["subnet4"]
                 if s["subnet"] == "10.20.0.0/24")
    assert staff["pools"][0]["client-class"] == "KNOWN"
    assert any("quarantine VLAN" in note for note in plan.notes)


def test_unbound_refuses_unlisted_networks(policy, ctx):
    content = _file(render_all(policy, ctx), UNBOUND_CONF_FILE).content
    assert "access-control: 10.20.0.0/24 allow" in content
    assert "access-control: 0.0.0.0/0 refuse" in content
    # DoT 업스트림과 호스트명 검증
    assert "forward-tls-upstream: yes" in content
    assert "forward-addr: 1.1.1.1@853#cloudflare-dns.com" in content


def test_unbound_switches_to_rpz_for_large_blocklists(policy_doc, ctx):
    policy_doc["dns"]["blocked_domains"] = [f"bad{i}.example.test" for i in range(600)]
    policy_doc["dns"]["allowed_domains"] = []
    policy = RouterPolicy.parse(policy_doc)
    plan = render_all(policy, ctx)
    content = _file(plan, UNBOUND_CONF_FILE).content
    assert "rpz:" in content
    zone = _file(plan, "/etc/unbound/mooker-rpz.zone").content
    assert "bad0.example.test CNAME ." in zone
    assert "*.bad599.example.test CNAME ." in zone


def test_qos_ingress_uses_ifb(policy, ctx):
    plan = render_all(policy, ctx)
    commands = [command.display() for command in plan.apply_commands]
    assert any("root cake bandwidth 95mbit" in c for c in commands)
    assert any("ifb-wan1 type ifb" in c for c in commands)
    assert any("dev ifb-wan1 root cake bandwidth 480mbit" in c and "ingress" in c
               for c in commands)


def test_networkd_dropins_assign_vlans(policy, ctx):
    plan = render_all(policy, ctx)
    bridge_netdev = _file(plan, "/etc/systemd/network/10-netplan-br-lan.netdev.d/50-mooker-l2.conf")
    assert "VLANFiltering=yes" in bridge_netdev.content
    access_port = _file(plan, "/etc/systemd/network/10-netplan-ens21.network.d/50-mooker-l2.conf")
    assert "PVID=20" in access_port.content and "EgressUntagged=20" in access_port.content
    trunk_port = _file(plan, "/etc/systemd/network/10-netplan-ens22.network.d/50-mooker-l2.conf")
    for vlan in (10, 20, 30, 99):
        assert f"VLAN={vlan}" in trunk_port.content


def test_wireguard_requires_secret_on_disk(policy_doc, ctx, tmp_path):
    policy_doc["mgmt_tunnel"]["enabled"] = True
    policy = RouterPolicy.parse(policy_doc)
    ctx.secret_dir = str(tmp_path)
    with pytest.raises(RenderError) as info:
        wg_render.render(policy, ctx)
    assert "개인키를 읽을 수 없다" in str(info.value)

    (tmp_path / "mgmt-wg-private").write_text("A" * 43 + "=")
    plan = wg_render.render(policy, ctx)
    config = plan.files[0]
    assert config.mode == 0o600  # 개인키가 들어가므로 반드시 0600
    assert "AllowedIPs = 10.88.0.0/24" in config.content
    # 무중단 갱신 경로를 쓴다 (관리 세션이 끊기지 않게)
    assert any("wg syncconf" in command.display() for command in plan.apply_commands)


def test_pppoe_preserves_existing_chap_secrets(policy_doc, ctx, tmp_path):
    policy_doc["wan_links"][0] = {
        "name": "wan1", "interface": "ens18", "mode": "pppoe", "metric": 100,
        "pppoe": {"username": "user@isp", "password_ref": "wan1-pppoe"},
    }
    policy = RouterPolicy.parse(policy_doc)
    (tmp_path / "wan1-pppoe").write_text("s3cr3t\n")
    ctx.secret_dir = str(tmp_path)
    ctx.existing_chap_secrets = '"other-user" * "keep-me" *\n'
    plan = pppoe_render.render(policy, ctx)
    secrets = next(t for t in plan.files if t.path.endswith("chap-secrets"))
    assert "keep-me" in secrets.content       # 고객 항목 보존
    assert "s3cr3t" in secrets.content        # 우리 항목 추가
    assert secrets.content.count("mooker-router managed") == 2
    assert secrets.mode == 0o600


def test_plan_detects_conflicting_paths(policy, ctx):
    plan = render_all(policy, ctx)
    from router.plan import FileTarget
    plan.files.append(FileTarget(NFT_INET_FILE, "다른 내용"))
    with pytest.raises(ValueError) as info:
        plan.finalize()
    assert "서로 다르게 생성한다" in str(info.value)
