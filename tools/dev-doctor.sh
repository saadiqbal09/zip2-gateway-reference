#!/usr/bin/env bash
#
# 개발 시작 전 환경 점검.
#
# 가장 흔한 실패는 "인터페이스 이름을 잘못 적어서 관리 접속이 끊기는 것"이다.
# 이 스크립트는 어느 NIC으로 SSH가 들어오고 있는지 확인해서, 그 NIC을 정책에
# 넣지 말라고 알려주고, 남은 NIC으로 정책 골격을 만들어 준다.
#
#   bash tools/dev-doctor.sh
#
set -uo pipefail

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
head_() { printf '\n\033[1;34m%s\033[0m\n' "$*"; }

FAIL=0

head_ "1. 시스템"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  if [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_ID:-}" = "24.04" ]; then
    ok "Ubuntu ${VERSION_ID} (검증된 버전)"
  else
    warn "${PRETTY_NAME:-unknown} — 24.04 LTS 기준으로 검증되었다"
  fi
fi
ok "커널 $(uname -r)"
ok "python3 $(python3 -V 2>&1 | cut -d' ' -f2)"

head_ "2. 관리 경로 — 이 NIC은 정책에 넣지 마라"
MGMT_IF=""
MGMT_PEER=""
if [ -n "${SSH_CLIENT:-}" ]; then
  MGMT_PEER="${SSH_CLIENT%% *}"
elif [ -n "${SSH_CONNECTION:-}" ]; then
  MGMT_PEER="${SSH_CONNECTION%% *}"
fi
if [ -n "$MGMT_PEER" ]; then
  MGMT_IF="$(ip -o route get "$MGMT_PEER" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)"
  MGMT_ADDR="$(ip -o -4 addr show dev "$MGMT_IF" 2>/dev/null | awk '{print $4}' | head -1)"
  bad "관리 NIC: $MGMT_IF ($MGMT_ADDR)  ← 정책의 어떤 필드에도 쓰지 않는다"
  ok  "접속 출발지: $MGMT_PEER"
  MGMT_CIDR="$(python3 - "$MGMT_ADDR" <<'PY' 2>/dev/null
import ipaddress, sys
try:
    print(ipaddress.ip_interface(sys.argv[1]).network)
except Exception:
    pass
PY
)"
  [ -n "$MGMT_CIDR" ] && ok "mgmt_allow_cidrs에 넣을 대역: $MGMT_CIDR"
else
  warn "SSH 세션이 아니다(콘솔?). 관리 NIC을 자동 판별할 수 없다."
  warn "  ip route get <개발PC IP> 로 직접 확인하라"
fi

head_ "3. 네트워크 인터페이스"
FREE=()
while read -r name _ state _; do
  case "$name" in lo|docker*|veth*|br-*|virbr*|wg*|ppp*|ifb-*) continue;; esac
  addr="$(ip -o -4 addr show dev "$name" 2>/dev/null | awk '{print $4}' | paste -sd, -)"
  driver="$(basename "$(readlink -f "/sys/class/net/$name/device/driver" 2>/dev/null)" 2>/dev/null)"
  carrier="$(cat "/sys/class/net/$name/carrier" 2>/dev/null)"
  link=$([ "$carrier" = "1" ] && echo "케이블 연결됨" || echo "케이블 없음")
  if [ "$name" = "$MGMT_IF" ]; then
    printf '  \033[31m%-12s\033[0m %-8s %-18s %-14s %s  ← 관리용, 사용 금지\n' \
      "$name" "$state" "${addr:--}" "$link" "${driver:-?}"
  else
    printf '  \033[32m%-12s\033[0m %-8s %-18s %-14s %s\n' \
      "$name" "$state" "${addr:--}" "$link" "${driver:-?}"
    FREE+=("$name")
  fi
done < <(ip -br link show 2>/dev/null)

COUNT=$(( ${#FREE[@]} ))
echo
if [ "$COUNT" -ge 2 ]; then
  ok "사용 가능한 NIC ${COUNT}개 → WAN 1개 + LAN 1개 구성 가능"
elif [ "$COUNT" -eq 1 ]; then
  warn "사용 가능한 NIC 1개 → WAN만 가능. LAN은 dummy(lab0)로 시뮬레이션한다"
else
  bad "관리 NIC 외에 쓸 수 있는 NIC이 없다. USB 이더넷 추가를 권한다"
  FAIL=1
fi

head_ "4. 필요한 도구"
for bin in nft netplan networkctl ip tc sysctl; do
  if command -v "$bin" >/dev/null 2>&1; then ok "$bin"; else bad "$bin 없음"; FAIL=1; fi
done
for bin in kea-dhcp4 unbound-checkconf wg pppd; do
  if command -v "$bin" >/dev/null 2>&1; then ok "$bin"
  else warn "$bin 없음 — sudo ./install.sh 로 설치된다"; fi
done
python3 -c 'import cryptography' 2>/dev/null && ok "python3-cryptography" || {
  bad "python3-cryptography 없음 (정책 서명 검증에 필수)"; FAIL=1; }
python3 -c 'import pytest' 2>/dev/null && ok "python3-pytest" || \
  warn "python3-pytest 없음 — sudo apt install python3-pytest"

head_ "5. 커널 기능"
modinfo sch_cake >/dev/null 2>&1 && ok "sch_cake (QoS)" || \
  warn "sch_cake 없음 — QoS가 fq_codel로 대체된다. linux-modules-extra-\$(uname -r) 확인"
modprobe -n nf_tables_bridge >/dev/null 2>&1 && ok "nf_tables_bridge (L2 격리)" || \
  warn "nf_tables_bridge 없음 — L2 격리가 적용되지 않는다(L3만 동작)"

head_ "6. 설치 상태"
if [ -L /opt/mooker-gateway ]; then
  ok "개발 모드 (링크 → $(readlink -f /opt/mooker-gateway))"
elif [ -d /opt/mooker-gateway ]; then
  warn "복사 설치본이다. 소스를 고쳐도 반영되지 않는다 → sudo DEV_LINK=1 ./install.sh"
else
  warn "아직 설치되지 않았다 → sudo DEV_LINK=1 ./install.sh"
fi
[ -x /usr/local/bin/mooker-router ] && ok "mooker-router CLI" || warn "CLI 미설치"
if ls /etc/mooker/trust/*.ed25519 >/dev/null 2>&1; then
  ok "신뢰 공개키: $(ls /etc/mooker/trust/*.ed25519 | xargs -n1 basename | paste -sd, -)"
else
  warn "정책 서명 공개키 없음 → tools/sign_policy.py keygen 후 /etc/mooker/trust/ 에 배치"
fi
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  if ss -lntup 2>/dev/null | grep -q ':53 '; then
    RES="$(ss -lntup 2>/dev/null | grep ':53 ' | head -1)"
    case "$RES" in
      *systemd-resolve*) warn "systemd-resolved가 53번을 잡고 있다 — install.sh가 스텁을 끈다";;
      *unbound*) ok "53번은 unbound가 쓰고 있다";;
    esac
  fi
fi

head_ "7. 정책 골격 (아래 값을 my-lab.yaml에 반영한다)"
if [ "$COUNT" -ge 2 ]; then
  WAN="${FREE[0]}"; LAN="${FREE[1]}"
elif [ "$COUNT" -eq 1 ]; then
  WAN="${FREE[0]}"; LAN="lab0   # dummy 인터페이스. 아래 안내대로 만든다"
else
  WAN="<없음>"; LAN="<없음>"
fi
cat <<SKEL

  wan_links:
    - name: wan1
      interface: $WAN
      mode: dhcp4
  bridges:
    - name: br-lab
      ports: [${LAN%% *}]
  firewall:
    mgmt_allow_cidrs:
      - ${MGMT_CIDR:-<개발PC 대역>}
      - 10.77.0.0/24
  commit_confirm: {mode: manual, timeout_s: 120}

SKEL
if [ "$COUNT" -le 1 ]; then
  cat <<'DUMMY'
  LAN용 dummy 인터페이스 만들기:
    sudo tee /etc/systemd/network/05-lab-dummy.netdev >/dev/null <<'NETDEV'
    [NetDev]
    Name=lab0
    Kind=dummy
    NETDEV
    sudo systemctl restart systemd-networkd && ip link show lab0

DUMMY
fi

head_ "결과"
if [ "$FAIL" -eq 0 ]; then
  ok "개발을 시작할 수 있다"
else
  bad "위의 ✗ 항목을 먼저 해결하라"
fi
exit "$FAIL"
