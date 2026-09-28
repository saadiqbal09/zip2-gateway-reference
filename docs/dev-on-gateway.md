# 게이트웨이에서 직접 개발하기 (VS Code Remote-SSH)

현재 구성을 전제로 한다.

```
[ 인터넷 ] ── [ 공유기 192.168.0.1 ]
                    ├── 유선 ── 게이트웨이  192.168.0.3   (개발 대상, Ubuntu 24.04)
                    └── 무선 ── 개발 PC     192.168.0.4   (VS Code)
```

목표는 두 단계다.
**Phase 1** — 공유기 뒤에서 SSH로 개발한다. 관리 접속을 절대 끊지 않는다.
**Phase 2** — 개발이 끝나면 공유기를 빼고 게이트웨이 WAN을 회선에 직결한다.

---

## 0. 먼저 확인할 것

게이트웨이의 VS Code 터미널에서 점검 스크립트를 돌린다. NIC 구성, 관리 NIC,
설치 상태, 커널 기능을 한 번에 확인하고 **실제 인터페이스 이름이 채워진 정책
골격**까지 출력한다.

```bash
cd <소스 디렉터리>          # 예: /home/mooker/router/gateway
bash tools/dev-doctor.sh
```

빨간 `✗`가 없으면 다음 단계로 간다. 아래는 이 스크립트가 확인하는 내용이다.

### 0-1. NIC이 몇 개인가

```bash
ip -br link
```

라우터를 개발하려면 **최소 2개**가 필요하다.

| NIC 수 | 구성 |
|---|---|
| 1개 | 관리 겸용. 실제 적용은 위험하므로 `render`/`plan`/`pytest`까지만. LAN은 dummy로 시뮬레이션 |
| 2개 | 관리 1 + WAN 1. LAN은 dummy 인터페이스로 시뮬레이션 (권장 시작점) |
| 3개 이상 | 관리 1 + WAN 1 + LAN 1. 실제 단말을 붙여 끝까지 시험 가능 |

2개뿐이면 USB 이더넷 어댑터 하나를 추가하는 것이 가장 값싼 해결이다.

### 0-2. 어느 NIC으로 SSH가 들어오는가 — 이 이름을 반드시 기억한다

```bash
ip route get 192.168.0.4        # dev 값이 관리 NIC이다
```

이 인터페이스는 **정책에 절대 넣지 않는다.** Router Plane은
`/etc/netplan/90-mooker.yaml` 하나만 소유하고 그 파일에는 정책에 등장하는
인터페이스만 들어간다. 관리 NIC이 정책에 없으면 기존 netplan 설정이 그대로
유지되고, 주소도 링크도 건드려지지 않는다.

### 0-3. 두 번째 접근 경로를 확보한다

SSH 하나에만 의존하지 않는다. 다음 중 하나는 반드시 준비한다.

- 모니터 + 키보드 (가장 확실)
- IPMI / iDRAC / BMC 콘솔
- 시리얼 콘솔
- 최소한: 다른 사람이 물리적으로 접근 가능한 위치

이 준비가 없으면 첫 `apply`를 하지 않는다.

---

## 1. 개발 환경 준비

### 1-1. SSH 키 로그인 (개발 PC에서)

```bash
ssh-keygen -t ed25519 -C "mooker-dev"          # 없다면
ssh-copy-id <user>@192.168.0.3
```

`~/.ssh/config`에 등록해 두면 VS Code가 알아서 잡는다.

```
Host mooker-gw
    HostName 192.168.0.3
    User <user>
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 20
    ServerAliveCountMax 3
```

`ServerAliveInterval`은 중요하다. 적용 실험 중 세션이 멈췄을 때 "끊긴 것인지
느린 것인지"를 빨리 알 수 있다.

### 1-2. 소스 배치 (게이트웨이에서)

소스 위치는 자유다. 홈 디렉터리(`/home/<user>/...`)도 된다 — 다만
`mooker-agent.service`가 `ProtectHome=yes`로 `/home`을 가리므로, 그대로 두면
Agent가 자기 코드를 못 읽고 ImportError로 죽는다. `DEV_LINK=1 ./install.sh`가
이 경우를 감지해 드롭인
(`/etc/systemd/system/mooker-agent.service.d/50-dev-source.conf`)으로 자동
완화한다. 운영 배포 시에는 그 드롭인을 지우고 `DEV_LINK` 없이 재설치한다.

`/srv` 아래에 두면 그 처리가 아예 필요 없다.

```bash
sudo install -d -o "$USER" -g "$USER" /srv/mooker-dev
```

개발 PC에서 소스를 올린다.

```bash
rsync -av --delete \
  --exclude '__pycache__' --exclude '.pytest_cache' --exclude 'node_modules' \
  ~/Downloads/"router dev"/2026-08-26/referenced-chatgpt-conversation-this-is-an/gateway/ \
  mooker-gw:/srv/mooker-dev/
```

이후에는 git을 쓰는 편이 낫다. 게이트웨이에서 `git clone` 하고 개발 PC와
같은 원격 저장소를 보게 한다.

### 1-3. VS Code Remote-SSH

1. 확장 **Remote - SSH** 설치
2. `F1` → *Remote-SSH: Connect to Host* → `mooker-gw`
3. 폴더 열기 → `/srv/mooker-dev`
4. 원격 쪽에 확장 설치: **Python**, **Pylance**
5. 인터프리터: `/usr/bin/python3`

`.vscode/settings.json` (원격에 생성):

```json
{
  "python.defaultInterpreterPath": "/usr/bin/python3",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests"],
  "python.analysis.extraPaths": ["."],
  "files.exclude": {"**/__pycache__": true, "**/.pytest_cache": true}
}
```

### 1-4. 개발 모드로 설치 — 복사 대신 링크

`install.sh`는 기본적으로 코드를 `/opt/mooker-gateway`로 **복사**한다. 그래서
소스를 고쳐도 반영되지 않는다. 개발 중에는 링크 모드를 쓴다.

```bash
cd <소스 디렉터리>          # 예: /home/mooker/router/gateway
sudo DEV_LINK=1 ./install.sh
```

`/opt/mooker-gateway` → 소스 디렉터리 심볼릭 링크가 만들어진다. 이제
편집한 코드가 재설치 없이 곧바로 반영된다.

| 고친 것 | 반영 방법 |
|---|---|
| `router/`, `agent/` 파이썬 코드 | CLI는 즉시. Agent는 `sudo systemctl restart mooker-agent` |
| `systemd/*.service` | `sudo DEV_LINK=1 ./install.sh` 재실행 |
| `install.sh` 자체 | 재실행 |

테스트에 pytest가 필요하다.

```bash
sudo apt install -y python3-pytest
python3 -m pytest tests/ -q          # sudo 불필요. root 없이 전부 돈다
```

---

## 2. 개발용 정책 만들기

`examples/policy.dev-lab.yaml`을 복사해 자기 장비에 맞게 고친다.

```bash
cp examples/policy.dev-lab.yaml /srv/mooker-dev/my-lab.yaml
```

반드시 확인할 네 곳:

```yaml
gateway_id: dev-lab-gateway          # mooker-router --gateway-id 와 일치
wan_links[0].interface: enp2s0       # ★ 공유기에 연결된 NIC (관리 NIC 아님!)
bridges[0].ports: [lab0]             # ★ LAN 포트. 없으면 아래 dummy
firewall.mgmt_allow_cidrs:
  - 192.168.0.0/24                   # ★ 개발 PC 대역. 빠지면 SSH 재접속 불가
  - 10.77.0.0/24
```

`commit_confirm.mode: manual`, `timeout_s: 120`이 들어 있다. 검증을 통과해도
사람이 `mooker-router confirm`을 칠 때까지 자동 복구 예약이 유지된다. **SSH가
끊기면 confirm을 칠 수 없으므로 2분 뒤 장비가 스스로 되돌아온다.** 원격 작업에서
이보다 나은 안전장치는 없다.

### LAN 포트가 없을 때 — dummy 인터페이스

```bash
sudo tee /etc/systemd/network/05-lab-dummy.netdev >/dev/null <<'EOF2'
[NetDev]
Name=lab0
Kind=dummy
EOF2
sudo systemctl restart systemd-networkd
ip link show lab0
```

Router Plane이 소유하지 않는 파일이므로 정책과 충돌하지 않는다. DHCP·DNS·NAT·
방화벽 규칙 생성과 검증 로직을 전부 시험할 수 있다(실제 단말 통신만 불가).

---

## 3. 정책 서명

```bash
cd /srv/mooker-dev
python3 tools/sign_policy.py keygen --key-id dev-lab --out ~/keys
sudo install -m 0644 ~/keys/dev-lab.ed25519 /etc/mooker/trust/

python3 tools/sign_policy.py sign \
  --policy my-lab.yaml --key ~/keys/dev-lab.key --key-id dev-lab \
  --bump --out /tmp/lab.signed.json
```

`--bump`는 revision을 1 올린다. **revision이 이전보다 크지 않으면 거부된다**
(되감기 방지). 정책을 고칠 때마다 `--bump`를 붙인다.

서명 전에 현장과 동일한 검증이 돌아간다. 여기서 걸리면 장비까지 갈 필요가 없다.

---

## 4. 안전한 개발 루프

```bash
# ① 코드/정책 수정 후 — root 없이
python3 -m pytest tests/ -q

# ② 적용 없이 결과 파일만 눈으로 확인
python3 -m router.cli --trust-dir ~/keys --gateway-id dev-lab-gateway \
  render --policy /tmp/lab.signed.json --out /tmp/review
find /tmp/review -type f | xargs -I{} sh -c 'echo "--- {}"; cat {}'

# ③ diff + 사전검사 (시스템 무변경)
sudo mooker-router --trust-dir ~/keys --gateway-id dev-lab-gateway \
  plan --policy /tmp/lab.signed.json

# ④ 사전검사까지만 실행
sudo mooker-router --trust-dir ~/keys --gateway-id dev-lab-gateway \
  apply --policy /tmp/lab.signed.json --dry-run

# ⑤ 실제 적용 — 여기서부터 시스템이 바뀐다
sudo mooker-router --trust-dir ~/keys --gateway-id dev-lab-gateway \
  apply --policy /tmp/lab.signed.json
```

⑤ 직후 **다른 터미널에서 새 SSH 연결이 되는지 반드시 확인한다.**

```bash
# 개발 PC의 다른 창에서
ssh mooker-gw 'echo 접속 정상'
```

되면 확정, 안 되면 아무것도 하지 않는다(2분 뒤 자동 복구).

```bash
sudo mooker-router confirm        # 접속이 살아 있을 때만
sudo mooker-router status
```

`--trust-dir`/`--gateway-id`를 매번 치기 번거로우면 셸 함수를 만든다.

```bash
mr() { sudo mooker-router --trust-dir ~/keys --gateway-id dev-lab-gateway "$@"; }
```

---

## 5. 사고가 났을 때

### SSH가 끊겼다
아무것도 하지 않고 2분 기다린다. `commit_confirm.timeout_s` 이후 타이머가
이전 설정으로 되돌린다. 그 뒤 다시 접속된다.

### 되돌아오지 않는다 — 콘솔에서

```bash
sudo mooker-router status                 # pending / 예약 상태 확인
sudo mooker-router rollback --reason "복구"
sudo journalctl -u mooker-router-rollback-* --no-pager
sudo tail -50 /var/log/mooker-router.log
```

### 최후 수단 — 수동 원복

```bash
sudo nft delete table inet mooker
sudo nft delete table bridge mooker_l2
sudo rm -f /etc/netplan/90-mooker.yaml
sudo rm -f /etc/systemd/network/*.d/50-mooker-l2.conf
sudo netplan apply
sudo systemctl restart systemd-networkd
```

우리 파일만 지우면 원래 설정으로 돌아간다. 고객/기존 설정은 애초에 건드리지 않는다.

### 스냅샷 확인

```bash
sudo mooker-router snapshots
sudo ls /var/lib/mooker-router/snapshots/<id>/
sudo cat /var/lib/mooker-router/snapshots/<id>/pre-apply-state.txt   # 적용 직전 커널 상태
```

---

## 6. 디버깅

```bash
# 적용 로그
sudo tail -f /var/log/mooker-router.log
sudo journalctl -u mooker-agent -f

# 실제 반영 상태
sudo nft list table inet mooker
ip -br addr
ip route
sudo systemctl status kea-dhcp4-server unbound systemd-networkd

# 방화벽에 걸려 버려지는 패킷
sudo journalctl -kf | grep mooker-drop

# 검증만 다시 돌리기
sudo mooker-router verify --no-wait

# 렌더 결과와 실제 파일 비교
sudo diff -u /etc/mooker/nftables/10-mooker-inet.nft \
             /tmp/review/etc/mooker/nftables/10-mooker-inet.nft
```

VS Code 디버거를 붙이려면 `debugpy`를 쓴다.

```bash
sudo apt install -y python3-debugpy
sudo python3 -m debugpy --listen 5678 --wait-for-client \
  -m router.cli --trust-dir ~/keys --gateway-id dev-lab-gateway \
  plan --policy /tmp/lab.signed.json
```

`.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [{
    "name": "Attach to mooker-router",
    "type": "debugpy",
    "request": "attach",
    "connect": {"host": "127.0.0.1", "port": 5678},
    "pathMappings": [{"localRoot": "${workspaceFolder}", "remoteRoot": "/srv/mooker-dev"}]
  }]
}
```

---

## 7. Phase 2 — 공유기를 빼고 WAN 직결

여기서 순서를 틀리면 반드시 접속을 잃는다. **회선을 바꾸기 전에 관리 경로를
먼저 옮긴다.**

### 7-0. 회선 종류를 먼저 확인한다

ISP가 DHCP인지 PPPoE인지에 따라 정책이 다르다. 모르면 공유기 관리 화면의
WAN 설정에서 확인한다. PPPoE라면 계정/비밀번호도 받아 둔다.

### 7-1. LAN을 실제 포트로 만든다

dummy(`lab0`)를 실제 NIC 이름으로 바꾸고 적용한다. 개발 PC를 그 포트에 **유선**
으로 연결한다.

```bash
# 개발 PC에서 — 게이트웨이 LAN 대역 주소를 받는지
ip addr show <유선 NIC>          # 10.77.0.x 를 받아야 한다
ping 10.77.0.1
```

### 7-2. 관리 경로를 LAN으로 옮긴다

LAN 주소로 SSH가 되는지 먼저 확인한다.

```bash
ssh <user>@10.77.0.1 'echo LAN 접속 정상'
```

**되는 것을 확인한 뒤에** `~/.ssh/config`의 HostName을 `10.77.0.1`로 바꾼다.
`mgmt_allow_cidrs`에서 `192.168.0.0/24`는 아직 지우지 않는다. 두 경로를 모두
살려 둔 상태로 다음 단계로 간다.

### 7-3. WAN 케이블을 교체한다

게이트웨이 WAN 포트의 케이블을 공유기에서 **회선(모뎀/ONU)** 으로 옮긴다.
이 시점에 무선(공유기) 경로는 끊긴다. LAN 유선 경로로 작업한다.

- **DHCP 회선**: 정책 변경 없이 그대로. `mooker-router verify`로 확인.
- **PPPoE 회선**: 정책을 고친다.

```bash
sudo sh -c 'umask 077; echo "<PPPoE 비밀번호>" > /etc/mooker/secrets/wan1-pppoe'
```

```yaml
wan_links:
  - name: wan1
    interface: enp2s0
    mode: pppoe
    metric: 100
    pppoe:
      username: "<ISP 계정>"
      password_ref: wan1-pppoe
      mtu: 1492
```

```bash
python3 tools/sign_policy.py sign --policy my-lab.yaml --key ~/keys/dev-lab.key \
  --key-id dev-lab --bump --out /tmp/lab.signed.json
mr apply --policy /tmp/lab.signed.json
mr confirm
```

PPPoE에서는 `mss_clamp: true`가 특히 중요하다(이미 켜져 있다). 없으면 일부
사이트만 열리지 않는 증상이 난다.

### 7-4. 정리

WAN 직결이 안정되면 마지막으로:

- `mgmt_allow_cidrs`에서 `192.168.0.0/24` 제거
- `dns.forwarders`를 공유기(`192.168.0.1`)에서 공용 resolver로 교체하고
  `forward_tls: true`
- `qos` 프로필 추가 (실측 속도의 90~95%로 상·하향 설정)
- VLAN 분리, AP 연결 (`policy.sample.yaml` 구조 참고)
- `commit_confirm.mode`를 `central`로 (중앙 플랫폼 연동 후)

---

## 요약 체크리스트

- [ ] `bash tools/dev-doctor.sh` 통과 (빨간 ✗ 없음)
- [ ] NIC 2개 이상, 관리 NIC 이름 확인
- [ ] 콘솔/모니터 등 두 번째 접근 경로 확보
- [ ] 관리 NIC을 정책에 넣지 않았다
- [ ] `mgmt_allow_cidrs`에 개발 PC 대역이 있다
- [ ] `commit_confirm.mode: manual`, `timeout_s: 120`
- [ ] `DEV_LINK=1 ./install.sh`로 링크 설치
- [ ] `pytest` → `render` → `plan` → `--dry-run` → `apply` 순서 준수
- [ ] `apply` 직후 **다른 창에서 새 SSH 연결 확인** 후에만 `confirm`
