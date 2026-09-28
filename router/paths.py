"""Router Plane이 소유하는 파일시스템 경로.

여기 열거된 경로만 쓰고, 여기 열거된 경로만 스냅샷/복구한다. 고객이 직접 관리하는
설정(예: 기존 /etc/nftables.conf 본문, 다른 netplan 파일)은 건드리지 않는다.
"""
from __future__ import annotations

# 상태/작업 디렉터리
STATE_DIR = "/var/lib/mooker-router"
STATE_FILE = f"{STATE_DIR}/state.json"
SNAPSHOT_DIR = f"{STATE_DIR}/snapshots"
SECRET_DIR = "/etc/mooker/secrets"
TRUST_DIR = "/etc/mooker/trust"
POLICY_CACHE = f"{STATE_DIR}/policy.current.json"
POLICY_LAST_GOOD = f"{STATE_DIR}/policy.last-good.json"
RUN_DIR = "/run/mooker-router"
LOG_FILE = "/var/log/mooker-router.log"
LOCK_FILE = f"{RUN_DIR}/apply.lock"

# 네트워크 설정 (우리가 생성하는 파일만)
NETPLAN_FILE = "/etc/netplan/90-mooker.yaml"
NETWORKD_DIR = "/etc/systemd/network"
NFT_DIR = "/etc/mooker/nftables"
NFT_INET_FILE = f"{NFT_DIR}/10-mooker-inet.nft"
NFT_BRIDGE_FILE = f"{NFT_DIR}/20-mooker-bridge.nft"
SYSCTL_FILE = "/etc/sysctl.d/90-mooker-router.conf"

# DHCP / DNS
KEA_DHCP4_FILE = "/etc/kea/kea-dhcp4.conf"
KEA_CTRL_SOCKET = "/run/kea/kea4-ctrl-socket"
UNBOUND_CONF_FILE = "/etc/unbound/unbound.conf.d/50-mooker.conf"
UNBOUND_BLOCK_FILE = "/etc/unbound/unbound.conf.d/51-mooker-blocklist.conf"
UNBOUND_RPZ_FILE = "/etc/unbound/mooker-rpz.zone"

# WireGuard
WG_DIR = "/etc/wireguard"

# QoS
QOS_STATE_FILE = f"{RUN_DIR}/qos.json"

# PPPoE
PPP_PEERS_DIR = "/etc/ppp/peers"
PPP_SECRETS_FILE = "/etc/ppp/chap-secrets"

# systemd 유닛
AGENT_UNIT = "mooker-agent.service"
ROLLBACK_UNIT_PREFIX = "mooker-router-rollback"
ROLLBACK_HELPER = "/usr/local/lib/mooker-router/rollback"
RESTORE_DYNAMIC_HELPER = "/usr/local/lib/mooker-router/restore-dynamic"
# 복구는 systemd 유닛에서 실행되므로 PATH에 기대지 않고 절대 경로를 쓴다.
MOOKER_ROUTER_BIN = "/usr/local/bin/mooker-router"

# 서비스 유닛 이름
UNIT_NETWORKD = "systemd-networkd.service"
UNIT_KEA4 = "kea-dhcp4-server.service"
UNIT_UNBOUND = "unbound.service"
UNIT_NFTABLES = "mooker-nftables.service"
