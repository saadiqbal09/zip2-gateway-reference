# Mooker Gateway Router Plane

Ubuntu 24.04 LTS 소프트웨어 라우터의 제어 계층. 중앙에서 서명된 선언형 정책을
받아 현장 네트워크를 구성한다. OpenWrt 의존성은 없고, Ubuntu 표준 도구만 쓴다.

## 1. 왜 이 순서인가

원격에서 라우터 설정을 바꿀 때 진짜 위험은 "설정이 틀렸다"가 아니라 **"바꾸는
순간 접속이 끊겨서 되돌릴 수 없다"** 이다. 그래서 파이프라인은 이 순서로 고정한다.

```
 ① 서명 검증        신뢰하지 않는 정책은 파싱조차 하지 않는다
 ② 스키마·베이스라인 검증   서브넷 충돌, 관리 경로 소실, WAN 인바운드 개방 거부
 ③ 렌더링           정책 → 설정 파일 + 명령 목록 (순수 함수, 멱등)
 ④ 사전검사(staging) netplan/nft/kea/unbound의 검증 모드로 확인 — 시스템 무변경
 ⑤ 스냅샷           되돌릴 지점 + 복구 절차를 디스크에 기록
 ⑥ 자동 복구 예약    ★ 적용 '전에' systemd 타이머를 건다
 ⑦ 적용             파일 쓰기 → netplan apply → nft -f → 서비스 → tc
 ⑧ 연결 검증        인터페이스/경로/DNS/제어채널/터널을 실제로 확인
 ⑨ confirm          중앙에 도달 가능하면 예약 해제, 아니면 자동 복구
```

⑥이 ⑦보다 앞에 있는 것이 이 설계의 핵심이다. 적용 도중에 프로세스가 죽거나
회선이 끊겨도 타이머는 커널/systemd에 남아 있으므로 장비가 스스로 돌아온다.
예약을 뒤에 두면 막고 싶었던 바로 그 사고를 막지 못한다.

②~④에서 실패하면 **시스템은 전혀 바뀌지 않는다**. ⑦~⑧에서 실패하면 **이전
상태로 복구된다**. 어중간한 상태로 끝나는 경로는 없다.

## 2. 구성 요소

| 파일 | 역할 |
|---|---|
| `router/model.py` | 정책 스키마와 의미 검증, 보안 baseline |
| `router/envelope.py` | Ed25519 서명 봉투 검증, 신뢰 저장소 |
| `router/render/` | 정책 → 설정/명령 컴파일러 (순수 함수) |
| `router/plan.py` | RenderPlan: 파일 + 사전검사 + 적용 명령 + 서비스 |
| `router/precheck.py` | staging 루트에서 도구별 검증 실행 |
| `router/snapshot.py` | 스냅샷 생성/복구, 적용 전 커널 상태 덤프 |
| `router/apply.py` | 파일 쓰기, 명령 실행, 잔여 파일 정리 |
| `router/verify.py` | 적용 후 실제 통신 확인 |
| `router/commitguard.py` | commit-confirm 자동 복구 예약/해제 |
| `router/controller.py` | 위 단계의 오케스트레이션 |
| `router/dynamic.py` | 즉시 격리/차단 (named set 원소) |
| `router/cli.py` | `mooker-router` 명령 |
| `agent/router_sync.py` | 중앙 ↔ Router Plane 연결, confirm 판단 |

## 3. 무엇이 무엇을 담당하는가

```
                 ┌──────────────── 정책(desired state) ────────────────┐
                 │ 중앙에서 서명. revision 단위. 분~일 단위로 바뀐다.   │
                 └───────────────────────┬────────────────────────────┘
                                         ▼
  sysctl ── netplan ── networkd 드롭인 ── pppoe ── nftables ── kea ── unbound ── wireguard ── tc
   포워딩    WAN/LAN     VLAN filtering    PPPoE   방화벽/NAT   DHCP    DNS 보안    관리터널    QoS
   rp_filter bridge/VRF  포트 PVID/격리                검역 셋

                 ┌──────────── 동적 원소(운영 판단) ──────────────────┐
                 │ 서명 없음. 초 단위. named set 원소만 바꾼다.        │
                 │ inet mooker: quarantine_mac/v4/v6, blocked_dst_*   │
                 │ bridge mooker_l2: quarantine_mac (L2 격리)         │
                 └────────────────────────────────────────────────────┘
```

정책 재적용은 nftables 테이블을 원자적으로 교체하므로 named set이 비워진다.
그래서 적용 직후 `restore-dynamic`이 `DynamicStore`의 내용을 되살린다. 이 저장소가
격리 상태의 단일 진실 공급원이다.

### netplan과 systemd-networkd를 함께 쓰는 이유

netplan은 WAN/LAN/bridge/VLAN/VRF를 간결하게 표현하지만, VLAN-aware bridge의
포트별 PVID/tagged 할당과 포트 격리를 표현하지 못한다. netplan은 자기 설정을
`/run/systemd/network/10-netplan-<이름>.{netdev,network}` 로 생성하고,
systemd-networkd는 같은 이름의 드롭인 디렉터리
`/etc/systemd/network/<파일명>.d/*.conf` 를 추가로 읽는다. 그래서 netplan 파일을
고쳐 쓰지 않고 `[Bridge] VLANFiltering=yes`, `[BridgeVLAN] PVID=`,
`[Bridge] Isolated=yes` 만 얹는다. 두 도구를 섞어 쓰는 가장 덜 위험한 방식이다.

PPPoE는 netplan도 systemd-networkd도 다루지 않으므로 `pppd` + `mooker-pppoe@.service`
로 처리한다. PPPoE에서는 L3가 `ppp-<wan이름>` 디바이스에 올라오므로 NAT/방화벽
규칙도 그 이름을 쓴다(`WanLink.link_interface`).

## 4. 소유하는 파일

우리가 만드는 파일만 건드린다. 고객이 이미 쓰고 있는 nftables 테이블, 다른
netplan 파일, chap-secrets의 기존 항목은 보존한다.

```
/etc/netplan/90-mooker.yaml                      netplan (0600)
/etc/systemd/network/*.{network,netdev}.d/50-mooker-l2.conf   L2 드롭인
/etc/mooker/nftables/10-mooker-inet.nft          inet mooker
/etc/mooker/nftables/20-mooker-bridge.nft        bridge mooker_l2
/etc/kea/kea-dhcp4.conf                          Kea DHCPv4
/etc/unbound/unbound.conf.d/50-mooker.conf       Unbound
/etc/unbound/mooker-rpz.zone                     대규모 차단 목록(RPZ)
/etc/wireguard/<iface>.conf                      관리 터널 (0600)
/etc/ppp/peers/mooker-<wan>                      PPPoE (0600)
/etc/ppp/chap-secrets                            Mooker 관리 블록만 교체
/etc/sysctl.d/90-mooker-router.conf              커널 파라미터
```

nftables는 절대 `flush ruleset`을 쓰지 않는다. `table ...; delete table ...;
table ... { }` 관용구로 우리 테이블만 하나의 트랜잭션에서 교체한다.

## 5. 보안 baseline (하위 정책이 완화할 수 없음)

중앙에서 잘못된 정책이 내려와도 다음은 지켜진다. 위반 시 `BaselineViolation`으로
거부되고 시스템은 손대지 않는다.

1. `firewall.mgmt_allow_cidrs`가 비어 있으면 거부 — 적용 후 아무도 접속할 수 없는
   상태를 만들지 않는다.
2. `mgmt_allow_cidrs`에 `0.0.0.0/0`, `::/0` 금지.
3. WAN zone에서 Gateway 자신으로의 서비스 개방 금지 — 인바운드 관리 포트를 열지
   않는다는 아키텍처 원칙. 필요한 노출은 `port_forwards`로 명시한다.
4. 관리 터널 `allowed_ips`에 전체 대역 금지 (최소 권한).
5. `require_central_confirm: true` 인데 `verify.require_control_plane: false` 금지 —
   확인 주체를 없애면서 확인을 요구할 수 없다.
6. commit-confirm 타임아웃 최소 60초.
7. nftables `output` chain은 항상 `policy accept` — 정책이 중앙 제어 채널을 스스로
   끊는 사고를 구조적으로 차단한다.

비밀값은 정책에 들어가지 않는다. `password_ref`, `private_key_ref`로 로컬 secret
파일(`/etc/mooker/secrets/`, 0600)을 참조한다. 스키마에 `password` 같은 평문 필드가
없으므로, 실수로 넣으면 "알 수 없는 항목"으로 거부된다.

## 6. commit-confirm

```
적용 직전:  systemd-run --unit=mooker-router-rollback-<snap> \
                        --on-active=<timeout>s --collect \
                        /usr/local/lib/mooker-router/rollback <snap>
```

`commit_confirm.mode`가 누가 확정하는지를 정한다.

| mode | 확정 주체 | 쓰는 곳 |
|---|---|---|
| `central` (기본) | 중앙 플랫폼. Agent가 적용 후 heartbeat로 도달 확인 후 confirm | 운영 |
| `manual` | 사람이 `mooker-router confirm` 실행 | 랩/개발, SSH 원격 작업 |
| `none` | 검증 통과 시 즉시 확정 | 콘솔이 확보된 장비만 |

- 검증 실패 → 타이머를 기다리지 않고 **즉시** 복구 + 예약 해제
- 검증 통과 + `mode: none` → 예약 해제, 확정
- 검증 통과 + `mode: central|manual` → 예약 유지, `pending` 상태

`manual`은 SSH로 원격 작업할 때의 정답이다. 접속이 끊기면 confirm을 칠 수 없으므로
타이머가 장비를 되돌린다. `mode: central`은 `verify.require_control_plane: true`를
요구한다(확인 주체의 도달성을 검증하지 않고 그 확인을 기다릴 수 없다). 중앙
플랫폼이 없는 장비는 `manual`을 쓴다.

구 스키마 `require_central_confirm: true/false`도 계속 받아들인다(각각 `central`/`none`).

`mode: central`의 `pending` 상태에서 확정 조건은 **"적용 후에도 중앙과 통신이 되는가"** 다.
Agent가 새 heartbeat를 보내 중앙이 응답하면 `confirm()`을 호출한다. 관리 경로가
살아 있다는 사실 자체가 가장 정확한 확인이고, 별도 승인 절차는 "승인을 기다리는
동안 이미 회선이 끊긴" 상황을 구분해 주지 못한다.

`pending` 중에는 새 정책을 받지 않는다. 되돌림 지점이 두 개 겹치면 어디로
복구해야 하는지 알 수 없어진다.

systemd 타이머를 쓸 수 없는 환경에서는 분리된 자식 프로세스로 대체하되, 보장이
약하다는 사실을 상태(`notes`)에 남긴다.

## 7. 운영 절차

### 설치

```bash
sudo ./install.sh          # 패키지, 코드, 유닛, 디렉터리
# 정책 서명 공개키 배치
sudo install -m 0644 mooker-policy-2026.ed25519 /etc/mooker/trust/
# 관리 터널을 쓰면
sudo sh -c 'umask 077; wg genkey > /etc/mooker/secrets/mgmt-wg-private'
sudo wg pubkey < /etc/mooker/secrets/mgmt-wg-private   # 중앙에 등록
```

### 정책 서명

Gateway는 서명되지 않은 정책을 받지 않는다. 운영에서는 중앙의 HSM/KMS가 서명해야
하지만, 그 파이프라인이 생기기 전까지는 `tools/sign_policy.py`를 쓴다.

```bash
# 키쌍 생성 (한 번만). 개인키는 중앙에, 공개키는 각 Gateway에.
python3 tools/sign_policy.py keygen --key-id mooker-policy-2026 --out ./keys
sudo install -m 0644 keys/mooker-policy-2026.ed25519 /etc/mooker/trust/

# 정책 문서에 서명 (JSON/YAML 모두 입력 가능, 서명 전에 검증도 돌린다)
python3 tools/sign_policy.py sign \
    --policy examples/policy.sample.yaml \
    --key keys/mooker-policy-2026.key --key-id mooker-policy-2026 \
    --gateway-id <이 장비의 gateway_id> --bump \
    --out /tmp/policy.signed.json

# 배포 전 확인
python3 tools/sign_policy.py check --envelope /tmp/policy.signed.json --trust-dir ./keys
```

개인키를 가진 누구든 모든 Gateway의 네트워크를 바꿀 수 있다. 운영 전환 시 HSM/KMS로
옮기고 파일 사본은 폐기한다.

### 첫 적용 (콘솔 접근이 가능한 상태에서)

```bash
mooker-router plan   --policy /tmp/policy.signed.json   # diff + 사전검사
mooker-router apply  --policy /tmp/policy.signed.json
mooker-router status                                    # pending 확인
mooker-router confirm                                   # 접속이 유지되면 확정
```

confirm하지 않으면 타임아웃 후 자동으로 되돌아간다. 첫 적용은 반드시 물리 콘솔
또는 IPMI 접근이 가능한 상태에서 한다.

### 일상 운영

```bash
mooker-router status                       # desired / applied / confirmed / pending
mooker-router verify --no-wait             # 현재 정책 기준 연결 점검
mooker-router snapshots                    # 되돌릴 지점 목록
mooker-router rollback --reason "회선 이상" # 즉시 되돌리기
mooker-router render --policy p.json --out /tmp/review   # 적용 없이 결과만 확인

# 즉시 격리 (정책 revision과 무관)
mooker-router quarantine add --mac AA:BB:CC:DD:EE:01 --ttl 1800 --reason "port scan"
mooker-router quarantine list
mooker-router quarantine remove --mac AA:BB:CC:DD:EE:01

mooker-router selftest                     # 서명→검증→렌더→사전검사 경로 점검
```

### Agent

```bash
sudo vi /etc/mooker/agent.env       # GATEWAY_ID, ENROLLMENT_TOKEN, ROUTER_PLANE=on
sudo systemctl enable --now mooker-agent
journalctl -u mooker-agent -f
```

안전 기본값: `ROUTER_PLANE=off`, `ENFORCEMENT_MODE=dry-run`, `COLLECTOR_MODE=fixture`.
현장 투입 시 각각 `on` / `nft` / `linux` 로 바꾼다.

## 8. 중앙 API

| 메서드 | 경로 | 용도 |
|---|---|---|
| POST | `/api/v1/admin/gateways/{id}/network-policy` | 서명된 봉투 업로드 |
| GET | `/api/v1/admin/gateways/{id}/network-policy` | desired vs reported 확인 |
| GET | `/api/v1/gateway/network-policy` | 현장이 정책 + 격리 목록을 가져간다 |
| POST | `/api/v1/gateway/network-policy/ack` | 현장 적용 결과 보고 |

백엔드는 봉투를 **보관하고 전달만** 한다. 서명 키를 갖지 않으므로, 백엔드가
침해되어도 위조 정책이 장비에 적용되지 않는다. 응답에서 `policy`/`signature`는
서명 대상이고 `enforcement`는 서명 대상이 아니다 — Agent가 이 둘을 분리해
처리한다.

## 9. 알려진 한계

- **비관리형 스위치 뒤의 단말**: bridge FDB는 "이 포트 뒤에 이 MAC이 있다"까지만
  알려준다. 개별 하위 포트는 식별 불가이며 `confidence: inferred`로 보고한다.
  관리형 스위치 식별(LLDP/SNMPv3)은 별도 수집기가 담당한다.
- **DHCP WAN + 정책 라우팅**: DHCP로 받은 소스 주소 기반 routing-policy는 부팅
  시점에 알 수 없다. netplan에는 metric만 반영되고, 소스 기반 규칙은 주소 획득
  후 채워야 한다(`notes`로 경고한다).
- **bridge nftables**: 커널에 `nf_tables_bridge`가 없으면 L2 검역이 적용되지
  않는다. 이 경우 L3 격리만 동작하고 같은 세그먼트 내부 통신은 networkd의
  `Isolated=` 설정에 의존한다. 적용 로그에 남는다.
- **Unbound < 1.17**: RPZ 미지원이므로 대규모 차단 목록이 `local-zone`으로
  생성되어 설정 파일이 커지고 reload가 느려진다.
- **CAKE 부재**: `sch_cake`가 없으면 `fq_codel`로 대체되고 상한 제어 정확도가
  떨어진다. `linux-modules-extra-$(uname -r)` 설치를 확인한다.
- **systemd-resolved**: 스텁 리스너(127.0.0.53)가 53번을 잡으면 Unbound가 뜨지
  못한다. `install.sh`가 `DNSStubListener=no`로 끈다.
- **Alembic 미도입**: 백엔드는 `create_all`로 스키마를 만든다. 운영 전에
  마이그레이션으로 교체해야 한다.

## 10. 테스트

```bash
cd gateway && python3 -m pytest tests/ -q
```

root 권한도, 실제 커널도, 인터넷도 필요하지 않다. 명령 실행은 `RecordingRunner`로,
파일 쓰기는 `file_root`로, DNS/HTTPS 프로브는 `NetworkProbes`로 가로챈다. 덕분에
"적용해 보기 전에는 알 수 없는" 코드가 남지 않는다.

주요 검증 항목:
- 사전검사 실패 시 파일이 하나도 쓰이지 않는다
- 자동 복구 예약이 적용보다 **먼저** 실행된다
- 적용/검증 실패 시 스냅샷 내용으로 정확히 되돌아간다
- 정책에서 사라진 VLAN의 드롭인 잔여 파일이 제거된다
- 정책 재적용 후에도 격리 원소가 L3/L2 셋에 되살아난다
- 봉투 위조·되감기·만료·대상 불일치가 모두 거부된다
