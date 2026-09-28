#!/usr/bin/env bash
#
# Mooker Gateway 현장 설치 스크립트 (Ubuntu 24.04 LTS)
#
# 하는 일
#   1. 필요한 패키지 설치 (nftables, netplan, Kea, Unbound, WireGuard, pppd, tc)
#   2. 충돌하는 기본 서비스 정리 (systemd-resolved 스텁, NetworkManager)
#   3. 코드를 /opt/mooker-gateway 로 배치
#   4. CLI 래퍼와 복구 헬퍼 설치
#   5. systemd 유닛 설치
#   6. 상태/비밀/신뢰 디렉터리 생성
#
# 하지 않는 일 (의도적)
#   - 정책을 적용하지 않는다. 설치와 적용은 분리한다.
#   - 서비스를 자동 시작하지 않는다. 등록 후 중앙에서 정책을 배포한다.
#
set -euo pipefail

MOOKER_HOME=/opt/mooker-gateway
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_APT="${SKIP_APT:-0}"
DRY_RUN="${DRY_RUN:-0}"
# DEV_LINK=1 : 코드를 복사하지 않고 이 소스 트리를 심볼릭 링크로 연결한다.
#              VS Code Remote-SSH로 게이트웨이에서 직접 개발할 때 쓴다.
#              편집한 내용이 재설치 없이 곧바로 반영된다.
DEV_LINK="${DEV_LINK:-0}"

log()  { printf '\033[1;34m[설치]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[주의]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[실패]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = "1" ]; then echo "  + $*"; else "$@"; fi; }

[ "$(id -u)" -eq 0 ] || die "root로 실행해야 한다 (sudo ./install.sh)"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ]; then
    warn "Ubuntu가 아닌 배포판(${ID:-unknown})이다. 경로와 패키지명이 다를 수 있다."
  elif [ "${VERSION_ID:-}" != "24.04" ]; then
    warn "24.04 LTS 기준으로 검증되었다. 현재 ${VERSION_ID:-unknown}."
  fi
fi

# ---------------------------------------------------------------------------
log "1/6 패키지 설치"
PACKAGES=(
  nftables conntrack iproute2
  netplan.io systemd-resolved
  kea-dhcp4-server
  unbound unbound-anchor
  wireguard-tools
  ppp pppoe
  ethtool tcpdump iputils-ping
  python3 python3-cryptography
)
if [ "$SKIP_APT" = "1" ]; then
  warn "SKIP_APT=1 이므로 패키지 설치를 건너뛴다"
else
  export DEBIAN_FRONTEND=noninteractive
  run apt-get update -qq
  run apt-get install -y --no-install-recommends "${PACKAGES[@]}"
  # CAKE는 linux-modules-extra에 들어 있다. 없으면 QoS 정확도가 떨어진다.
  if ! modinfo sch_cake >/dev/null 2>&1; then
    warn "sch_cake 모듈이 없다. linux-modules-extra 설치를 시도한다."
    run apt-get install -y --no-install-recommends "linux-modules-extra-$(uname -r)" || \
      warn "설치 실패. QoS는 fq_codel로 대체된다."
  fi
fi

# ---------------------------------------------------------------------------
log "2/6 충돌 서비스 정리"
# NetworkManager와 netplan/networkd를 함께 쓰면 인터페이스 소유권이 흔들린다.
if systemctl list-unit-files NetworkManager.service >/dev/null 2>&1 && \
   systemctl is-enabled NetworkManager.service >/dev/null 2>&1; then
  warn "NetworkManager를 비활성화한다 (netplan renderer는 networkd를 쓴다)"
  run systemctl disable --now NetworkManager.service || true
fi
run systemctl enable systemd-networkd.service

# systemd-resolved의 127.0.0.53 스텁이 53번 포트를 잡으면 Unbound가 뜨지 못한다.
# resolved는 남겨두되 스텁 리스너만 끄고, /etc/resolv.conf는 로컬 Unbound로 향하게 한다.
if systemctl is-active systemd-resolved.service >/dev/null 2>&1; then
  log "systemd-resolved 스텁 리스너를 끈다 (Unbound가 53번을 쓴다)"
  run mkdir -p /etc/systemd/resolved.conf.d
  if [ "$DRY_RUN" != "1" ]; then
    cat > /etc/systemd/resolved.conf.d/90-mooker.conf <<'RESOLVED'
# Mooker Gateway: 로컬 Unbound가 53번 포트를 소유한다.
[Resolve]
DNSStubListener=no
DNS=127.0.0.1
RESOLVED
  fi
  run systemctl restart systemd-resolved.service
fi

# ---------------------------------------------------------------------------
if [ "$DEV_LINK" = "1" ]; then
  log "3/6 개발 모드: $MOOKER_HOME -> $SRC_DIR (심볼릭 링크)"
  warn "개발 모드다. 소스 트리를 고치면 즉시 반영된다. 운영 장비에는 쓰지 않는다."
  if [ -e "$MOOKER_HOME" ] && [ ! -L "$MOOKER_HOME" ]; then
    run mv "$MOOKER_HOME" "${MOOKER_HOME}.replaced-$(date +%s)"
    warn "기존 설치본을 ${MOOKER_HOME}.replaced-* 로 옮겼다"
  fi
  run rm -f "$MOOKER_HOME"
  run ln -sfn "$SRC_DIR" "$MOOKER_HOME"

  # mooker-agent.service는 ProtectHome=yes 로 /home을 가린다. 소스가 홈 디렉터리
  # 아래에 있으면 서비스가 자기 코드를 읽지 못하고 ImportError로 죽는다.
  # 개발 모드에서만 드롭인으로 완화한다(운영 설치본에는 적용되지 않는다).
  case "$SRC_DIR" in
    /home/*|/root/*)
      warn "소스가 홈 디렉터리에 있다($SRC_DIR). Agent 서비스용 드롭인을 설치한다."
      run mkdir -p /etc/systemd/system/mooker-agent.service.d
      if [ "$DRY_RUN" != "1" ]; then
        cat > /etc/systemd/system/mooker-agent.service.d/50-dev-source.conf <<DROPIN
# 개발 모드 전용. 소스가 /home 아래에 있어 ProtectHome을 완화한다.
# 운영 배포 시 이 파일을 지우고 DEV_LINK 없이 재설치한다:
#   rm -rf /etc/systemd/system/mooker-agent.service.d && ./install.sh
[Service]
ProtectHome=read-only
Environment=PYTHONDONTWRITEBYTECODE=1
DROPIN
        chmod 0644 /etc/systemd/system/mooker-agent.service.d/50-dev-source.conf
      fi
      # 홈 디렉터리가 0750이면 root는 읽지만, 경로 각 단계의 실행권한을 확인해 둔다.
      run chmod o+x "$(dirname "$SRC_DIR")" 2>/dev/null || true
      ;;
  esac
else
  log "3/6 코드 배치: $MOOKER_HOME"
  run mkdir -p "$MOOKER_HOME"
  for item in agent router examples docs tools; do
    [ -e "$SRC_DIR/$item" ] || continue
    run rm -rf "$MOOKER_HOME/$item"
    run cp -a "$SRC_DIR/$item" "$MOOKER_HOME/"
  done
  run find "$MOOKER_HOME" -name '__pycache__' -type d -prune -exec rm -rf {} +
  run chown -R root:root "$MOOKER_HOME"
  run chmod -R go-w "$MOOKER_HOME"
fi

# ---------------------------------------------------------------------------
log "4/6 CLI 래퍼와 복구 헬퍼"
run install -D -m 0755 "$SRC_DIR/bin/mooker-router" /usr/local/bin/mooker-router
run install -D -m 0755 "$SRC_DIR/lib/rollback" /usr/local/lib/mooker-router/rollback
run install -D -m 0755 "$SRC_DIR/lib/restore-dynamic" /usr/local/lib/mooker-router/restore-dynamic

# ---------------------------------------------------------------------------
log "5/6 systemd 유닛"
for unit in mooker-nftables.service mooker-agent.service 'mooker-pppoe@.service'; do
  run install -D -m 0644 "$SRC_DIR/systemd/$unit" "/etc/systemd/system/$unit"
done
run systemctl daemon-reload
# nftables 유닛은 부팅 시 우리 테이블을 되살려야 하므로 활성화한다.
# Agent는 등록(enroll) 후 운영자가 켠다.
run systemctl enable mooker-nftables.service

# ---------------------------------------------------------------------------
log "6/6 디렉터리와 권한"
run install -d -m 0750 /etc/mooker
run install -d -m 0700 /etc/mooker/secrets
run install -d -m 0755 /etc/mooker/trust
run install -d -m 0750 /etc/mooker/nftables
run install -d -m 0750 /var/lib/mooker-router
run install -d -m 0750 /var/lib/mooker-router/snapshots
run install -d -m 0750 /var/lib/mooker-agent
run install -d -m 0755 /var/lib/kea
run install -d -m 0755 /run/mooker-router

if [ ! -f /etc/mooker/agent.env ] && [ "$DRY_RUN" != "1" ]; then
  cat > /etc/mooker/agent.env <<'ENVFILE'
# Mooker Gateway Agent 환경 설정
PLATFORM_URL=https://api.mooker.io
GATEWAY_NAME=
GATEWAY_ID=
ENROLLMENT_TOKEN=
# Router Plane: on 으로 두면 중앙 네트워크 정책을 실제로 적용한다.
ROUTER_PLANE=off
# 수집/집행 모드
COLLECTOR_MODE=linux
ENFORCEMENT_MODE=dry-run
INTERVAL_SECONDS=30
ENVFILE
  chmod 0640 /etc/mooker/agent.env
  log "/etc/mooker/agent.env 생성 (등록 정보를 채워야 한다)"
fi

# 초기 nftables 파일이 없으면 유닛이 실패한다. 통과 전용 최소 룰셋을 둔다.
if [ ! -f /etc/mooker/nftables/10-mooker-inet.nft ] && [ "$DRY_RUN" != "1" ]; then
  cat > /etc/mooker/nftables/10-mooker-inet.nft <<'BOOTSTRAP'
# 부트스트랩 룰셋. 정책이 적용되기 전까지 아무것도 차단하지 않는다.
# 첫 정책 적용 시 Router Plane이 이 파일을 대체한다.
table inet mooker
delete table inet mooker
table inet mooker {
    chain input   { type filter hook input   priority filter; policy accept; }
    chain forward { type filter hook forward priority filter; policy accept; }
}
BOOTSTRAP
  chmod 0640 /etc/mooker/nftables/10-mooker-inet.nft
  warn "부트스트랩 nftables 룰셋을 설치했다(모두 허용). 첫 정책 적용 전까지 유효하다."
fi

if [ "$DEV_LINK" = "1" ]; then
  cat <<'DEVNEXT'

개발 모드 설치 완료.

  코드 위치      : 소스 트리 그대로 (심볼릭 링크)
  즉시 반영 대상  : mooker-router CLI, mooker-agent 서비스
  재설치가 필요한 때: systemd 유닛 파일, install.sh 자체를 고쳤을 때

  개발 루프:
    python3 -m pytest tests/ -q                       # 코드 수정 후 (sudo 불필요)
    sudo mooker-router plan  --policy /tmp/p.json      # 무엇이 바뀌는지
    sudo mooker-router apply --policy /tmp/p.json --dry-run
    sudo mooker-router apply --policy /tmp/p.json
    sudo mooker-router confirm                         # 접속이 유지되면
    sudo mooker-router rollback                        # 아니면 즉시 되돌리기

  Agent를 재시작해야 코드 변경이 반영된다:
    sudo systemctl restart mooker-agent

DEVNEXT
  exit 0
fi

cat <<'NEXT'

설치 완료. 다음 순서로 진행한다.

  1) 중앙에서 이 Gateway를 등록하고 gateway_id / enrollment_token을 받는다.
       /etc/mooker/agent.env 에 기록한다.

  2) 정책 서명 공개키를 신뢰 저장소에 배치한다.
       install -m 0644 mooker-policy-2026.ed25519 /etc/mooker/trust/

  3) 관리 터널을 쓰면 WireGuard 개인키를 만든다.
       umask 077; wg genkey > /etc/mooker/secrets/mgmt-wg-private
       wg pubkey < /etc/mooker/secrets/mgmt-wg-private   # 중앙에 등록할 공개키

  4) 적용 전에 반드시 계획을 확인한다.
       mooker-router plan --policy /tmp/policy.signed.json

  5) 첫 적용은 콘솔(물리 또는 IPMI) 접근이 가능한 상태에서 한다.
       mooker-router apply --policy /tmp/policy.signed.json
       mooker-router status          # pending 확인
       mooker-router confirm         # 접속이 유지되면 확정

     confirm하지 않으면 commit-confirm 타임아웃 후 자동으로 되돌아간다.

  6) Agent를 켠다.
       systemctl enable --now mooker-agent

NEXT
