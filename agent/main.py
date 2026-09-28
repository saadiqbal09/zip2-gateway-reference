"""Mooker Gateway Agent.

역할은 셋이다.
  1. 중앙과의 outbound 제어 채널 유지 (enroll / heartbeat / inventory)
  2. 현장 관측 (단말 발견, 접속 위치, Wi-Fi/스위치 토폴로지)
  3. 중앙 정책의 현장 반영 — 단, 직접 명령을 실행하지 않고 Router Plane에 위임한다

3번이 이전 버전과 달라진 부분이다. Agent가 ip/nft/tc를 직접 호출하면, 실패했을 때
되돌릴 지점이 없고 무엇이 왜 바뀌었는지도 알 수 없다. 이제 네트워크 변경은 모두
router 패키지의 NetworkController를 지나간다: 서명 검증 → 사전검사 → 스냅샷 →
자동 복구 예약 → 적용 → 연결 검증 → confirm.

안전 기본값
  ROUTER_PLANE=off      : 네트워크 정책을 적용하지 않는다(관측/보고만)
  ENFORCEMENT_MODE=dry-run : 차단을 실제로 걸지 않는다
  COLLECTOR_MODE=fixture   : 예시 인벤토리를 보고한다
현장 투입 시 각각을 on / nft / linux 로 바꾼다.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# /opt/mooker-gateway 를 import 경로에 넣어 router 패키지를 함께 쓴다.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PLATFORM_URL = os.getenv("PLATFORM_URL", "http://127.0.0.1:8080").rstrip("/")
GATEWAY_NAME = os.getenv("GATEWAY_NAME", "mooker-gateway")
ENROLLMENT_TOKEN = os.getenv("ENROLLMENT_TOKEN", "")
STATE_PATH = Path(os.getenv("STATE_PATH", "/var/lib/mooker-agent/state.json"))
FIXTURE_PATH = Path(os.getenv("FIXTURE_PATH", "/examples/inventory.json"))
COLLECTOR_MODE = os.getenv("COLLECTOR_MODE", "fixture")
ENFORCEMENT_MODE = os.getenv("ENFORCEMENT_MODE", "dry-run")
ROUTER_PLANE = os.getenv("ROUTER_PLANE", "off").lower() in {"on", "true", "1", "yes"}
ROUTER_TRUST_DIR = os.getenv("ROUTER_TRUST_DIR", "/etc/mooker/trust")
ROUTER_ALLOW_HMAC = os.getenv("ROUTER_ALLOW_HMAC", "0") in {"1", "true", "yes"}
INTERVAL_SECONDS = max(10, int(os.getenv("INTERVAL_SECONDS", "30")))
AGENT_VERSION = "0.2.0"
MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


def log(message: str, *args: Any) -> None:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{stamp} {message % args if args else message}", flush=True)


# ---------------------------------------------------------------------------
# 로컬 상태
# ---------------------------------------------------------------------------
def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(STATE_PATH)


# ---------------------------------------------------------------------------
# 중앙 통신 (outbound only, HMAC 서명)
# ---------------------------------------------------------------------------
class PlatformError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        self.status = status
        super().__init__(message)


def request(method: str, path: str, payload: dict | None = None,
            state: dict | None = None, timeout: float = 10.0) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    headers = {"Content-Type": "application/json"}
    if state and state.get("gateway_id") and state.get("agent_secret"):
        timestamp = str(int(time.time()))
        canonical = b"\n".join([method.encode(), path.encode(), timestamp.encode(), body])
        headers.update({
            "X-Gateway-ID": state["gateway_id"],
            "X-Timestamp": timestamp,
            "X-Signature": hmac.new(state["agent_secret"].encode(), canonical,
                                    hashlib.sha256).hexdigest(),
        })
    req = urllib.request.Request(PLATFORM_URL + path, body or None, headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise PlatformError(
            f"platform HTTP {exc.code}: {exc.read().decode(errors='replace')[:300]}",
            status=exc.code) from exc
    except urllib.error.URLError as exc:
        raise PlatformError(f"platform unreachable: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise PlatformError(f"platform 응답이 JSON이 아니다: {exc}") from exc


def enroll(state: dict) -> dict:
    if state.get("gateway_id") and state.get("agent_secret"):
        return state
    gateway_id = os.getenv("GATEWAY_ID", "")
    if not gateway_id or not ENROLLMENT_TOKEN:
        raise RuntimeError("첫 등록에는 GATEWAY_ID와 ENROLLMENT_TOKEN이 필요하다")
    response = request("POST", "/api/v1/gateway/enroll",
                       {"gateway_id": gateway_id, "enrollment_token": ENROLLMENT_TOKEN,
                        "agent_version": AGENT_VERSION})
    state.update(response)
    save_state(state)
    log("등록 완료: gateway_id=%s", state.get("gateway_id"))
    return state


# ---------------------------------------------------------------------------
# 인벤토리 수집
# ---------------------------------------------------------------------------
def normalize_mac(value: str) -> str:
    value = value.upper().replace("-", ":")
    if not MAC_RE.fullmatch(value):
        raise ValueError(f"invalid MAC: {value!r}")
    return value


def fixture_inventory() -> dict:
    try:
        data = json.loads(FIXTURE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {"devices": [], "nodes": []}
    for device in data.get("devices", []):
        device["mac"] = normalize_mac(device["mac"])
    return data


def _run(argv: list[str], timeout: float = 5.0) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                              check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _neighbour_map() -> dict[str, list[str]]:
    """ARP/NDP 테이블에서 MAC -> IP 목록을 만든다."""
    mapping: dict[str, list[str]] = {}
    output = _run(["ip", "-json", "neigh", "show"])
    if not output:
        return mapping
    try:
        entries = json.loads(output)
    except json.JSONDecodeError:
        return mapping
    for entry in entries:
        mac, address = entry.get("lladdr"), entry.get("dst")
        if not mac or not address:
            continue
        try:
            key = normalize_mac(mac)
        except ValueError:
            continue
        mapping.setdefault(key, []).append(address)
    return mapping


def get_wifi_stations() -> tuple[list[dict], list[dict]]:
    """무선 단말과 AP 노드를 수집한다.

    hostapd/iw가 없는 환경에서는 빈 결과를 돌려준다. 무선 정보가 없다는 사실을
    '유선'으로 오인 보고하지 않는 것이 중요하다 — 접속 위치가 틀리면 격리 대상을
    잘못 고른다.
    """
    devices: list[dict] = []
    nodes: list[dict] = []
    interfaces = re.findall(r"Interface (\S+)", _run(["iw", "dev"]))
    for interface in interfaces:
        info = _run(["iw", "dev", interface, "info"])
        ssid_match = re.search(r"ssid (\S+)", info)
        channel_match = re.search(r"channel (\d+).*?(\d+) MHz", info)
        ssid = ssid_match.group(1) if ssid_match else ""
        frequency = int(channel_match.group(2)) if channel_match else 0
        band = "6GHz" if frequency >= 5955 else ("5GHz" if frequency >= 5000 else
                                                ("2.4GHz" if frequency else ""))
        node_key = f"ap:{interface}"
        nodes.append({
            "node_key": node_key, "node_type": "ap", "parent_key": None,
            "details": {"interface": interface, "ssid": ssid, "band": band,
                        "frequency_mhz": frequency},
        })
        current: dict | None = None
        for line in _run(["iw", "dev", interface, "station", "dump"]).splitlines():
            station = re.match(r"Station ([0-9a-fA-F:]{17})", line.strip())
            if station:
                try:
                    mac = normalize_mac(station.group(1))
                except ValueError:
                    current = None
                    continue
                current = {
                    "mac": mac, "ip_addresses": [], "hostname": "Unknown",
                    "attachment": {"kind": "wireless", "confidence": "confirmed",
                                   "node_key": node_key, "port": None, "vlan_id": None,
                                   "ssid": ssid or None, "bssid": None, "band": band or None,
                                   "rssi_dbm": None},
                }
                devices.append(current)
                continue
            if current is None:
                continue
            signal = re.search(r"signal:\s*(-?\d+)", line)
            if signal:
                current["attachment"]["rssi_dbm"] = int(signal.group(1))
    return devices, nodes


def linux_inventory() -> dict:
    """리눅스 커널이 확실히 아는 것만 보고한다.

    bridge FDB는 '이 포트 뒤에 이 MAC이 있다'까지만 말해준다. 비관리형 스위치가
    끼어 있으면 그 아래 물리 포트는 알 수 없다. 그래서 confidence를 'inferred'로
    두고, 관리형 스위치 식별은 LLDP/SNMPv3 수집기(별도 모듈)가 담당한다.
    """
    devices: list[dict] = []
    nodes: list[dict] = []
    neighbours = _neighbour_map()

    output = _run(["bridge", "-json", "fdb", "show"])
    entries: list[dict] = []
    if output:
        try:
            entries = json.loads(output)
        except json.JSONDecodeError:
            entries = []
    if entries:
        for entry in entries:
            mac, interface = entry.get("mac"), entry.get("ifname")
            flags = entry.get("flags") or []
            if not mac or not interface or "self" in flags or entry.get("state") == "permanent":
                continue
            try:
                key = normalize_mac(mac)
            except ValueError:
                continue
            devices.append({
                "mac": key,
                "ip_addresses": sorted(set(neighbours.get(key, [])))[:16],
                "hostname": "Unknown",
                "attachment": {"kind": "wired", "confidence": "inferred",
                               "node_key": f"bridge:{entry.get('master', 'gateway')}",
                               "port": interface, "vlan_id": entry.get("vlan"),
                               "ssid": None, "bssid": None, "band": None, "rssi_dbm": None},
            })
    else:
        # bridge 명령의 JSON 미지원 버전 대비 텍스트 파싱 경로
        for line in _run(["bridge", "fdb", "show"]).splitlines():
            fields = line.split()
            if len(fields) < 3 or "dev" not in fields:
                continue
            if "self" in fields or "permanent" in fields:
                continue
            try:
                key = normalize_mac(fields[0])
                interface = fields[fields.index("dev") + 1]
            except (ValueError, IndexError):
                continue
            devices.append({
                "mac": key, "ip_addresses": sorted(set(neighbours.get(key, [])))[:16],
                "hostname": "Unknown",
                "attachment": {"kind": "wired", "confidence": "inferred",
                               "node_key": "gateway", "port": interface, "vlan_id": None,
                               "ssid": None, "bssid": None, "band": None, "rssi_dbm": None},
            })

    wifi_devices, wifi_nodes = get_wifi_stations()
    # 무선으로 확인된 MAC은 FDB의 'inferred 유선' 판정보다 신뢰도가 높다.
    wireless_macs = {device["mac"] for device in wifi_devices}
    devices = [device for device in devices if device["mac"] not in wireless_macs]
    devices.extend(wifi_devices)
    nodes.extend(wifi_nodes)
    return {"devices": devices, "nodes": nodes}


def collect_inventory() -> dict:
    return fixture_inventory() if COLLECTOR_MODE == "fixture" else linux_inventory()


# ---------------------------------------------------------------------------
# 집행 (Router Plane 미사용 시의 독립 경로)
# ---------------------------------------------------------------------------
class LegacyEnforcement:
    """Router Plane이 꺼져 있을 때 쓰는 독립 nftables 테이블.

    고객이 이미 운영 중인 방화벽을 대체하지 않기 위해 전용 테이블
    ``inet mooker_agent``만 만들고, 그 안에서만 차단한다. Router Plane을 켜면
    격리는 ``inet mooker``/``bridge mooker_l2``의 named set으로 옮겨간다.
    """

    TABLE = "mooker_agent"

    def __init__(self, mode: str):
        self.mode = mode
        self._initialized = False

    def _ensure_table(self) -> None:
        if self._initialized:
            return
        exists = subprocess.run(["nft", "list", "table", "inet", self.TABLE],
                                capture_output=True, timeout=5).returncode == 0
        if not exists:
            script = "\n".join([
                f"add table inet {self.TABLE}",
                f"add set inet {self.TABLE} whitelist_macs {{ type ether_addr; }}",
                f"add set inet {self.TABLE} quarantine_macs {{ type ether_addr; flags timeout; }}",
                f"add chain inet {self.TABLE} mooker_forward "
                f"{{ type filter hook forward priority -10; policy accept; }}",
                f"add rule inet {self.TABLE} mooker_forward "
                f"ether saddr @quarantine_macs counter drop",
                f"add rule inet {self.TABLE} mooker_forward "
                f"ether daddr @quarantine_macs counter drop",
                "",
            ])
            result = subprocess.run(["nft", "-f", "-"], input=script.encode(),
                                    capture_output=True, timeout=8)
            if result.returncode:
                raise RuntimeError("nft 초기화 실패: " + result.stderr.decode(errors="replace"))
        self._initialized = True

    def apply(self, policy: dict) -> dict:
        macs = [normalize_mac(item["mac"]) for item in policy.get("whitelist", [])
                if item.get("mac")]
        quarantine = [normalize_mac(item["mac"]) for item in policy.get("quarantine", [])
                      if item.get("mac")]
        if self.mode == "dry-run":
            return {"mode": "dry-run", "whitelisted": len(macs), "quarantined": len(quarantine)}
        if self.mode != "nft":
            raise RuntimeError(f"지원하지 않는 집행 모드: {self.mode}")
        self._ensure_table()
        script = [f"flush set inet {self.TABLE} whitelist_macs"]
        if macs:
            script.append(f"add element inet {self.TABLE} whitelist_macs "
                          f"{{ {', '.join(macs)} }}")
        script.append(f"flush set inet {self.TABLE} quarantine_macs")
        if quarantine:
            script.append(f"add element inet {self.TABLE} quarantine_macs "
                          f"{{ {', '.join(quarantine)} }}")
        result = subprocess.run(["nft", "-f", "-"], input=("\n".join(script) + "\n").encode(),
                                capture_output=True, timeout=8)
        if result.returncode:
            raise RuntimeError("nft 적용 실패: " + result.stderr.decode(errors="replace"))
        return {"mode": "nft", "whitelisted": len(macs), "quarantined": len(quarantine)}


class RouterPlaneEnforcement:
    """Router Plane이 소유한 named set에 격리 원소를 넣는다.

    정책 재적용으로 테이블이 교체되어도 DynamicStore가 진실을 갖고 있어 복원된다.
    L2(bridge) 셋에도 함께 반영하므로, 격리 단말이 같은 VLAN의 옆 단말을 계속
    공격하는 상황을 막는다.
    """

    def __init__(self, mode: str):
        from router.dynamic import DynamicStore
        from router.util import SubprocessRunner

        self.mode = mode
        self.store = DynamicStore()
        self.runner = SubprocessRunner()

    def apply(self, policy: dict) -> dict:
        from router.dynamic import from_central_payload, sync

        elements = from_central_payload({"quarantine": policy.get("quarantine", [])})
        if self.mode == "dry-run":
            return {"mode": "dry-run", "quarantined": len(elements),
                    "note": "ENFORCEMENT_MODE=nft 로 바꾸면 실제로 차단한다"}
        self.store.replace(elements)
        report = sync(self.runner, self.store)
        return {"mode": "nft", "quarantined": len(elements), "sets_ok": report["ok"]}


# ---------------------------------------------------------------------------
# 메인 루프
# ---------------------------------------------------------------------------
def build_router_sync(state: dict):
    if not ROUTER_PLANE:
        return None
    try:
        from agent.router_sync import RouterPlaneSync
    except ImportError as exc:
        log("Router Plane 모듈을 불러올 수 없다(%s). 관측 전용으로 계속한다.", exc)
        return None
    return RouterPlaneSync(state.get("gateway_id"), allow_hmac=ROUTER_ALLOW_HMAC,
                           trust_dir=ROUTER_TRUST_DIR)


def run() -> None:
    log("Mooker Gateway Agent %s 시작 (collector=%s enforcement=%s router_plane=%s)",
        AGENT_VERSION, COLLECTOR_MODE, ENFORCEMENT_MODE, "on" if ROUTER_PLANE else "off")
    state = enroll(load_state())
    enforcement = RouterPlaneEnforcement(ENFORCEMENT_MODE) if ROUTER_PLANE \
        else LegacyEnforcement(ENFORCEMENT_MODE)
    router = build_router_sync(state)
    last_revision = -1
    last_sync: dict[str, Any] = {"stage": "idle"}

    def heartbeat() -> dict | None:
        """중앙 도달 확인 겸 상태 보고. 실패 시 None."""
        health = {
            "agent": "healthy",
            "agent_version": AGENT_VERSION,
            "gateway_name": GATEWAY_NAME,
            "collector_mode": COLLECTOR_MODE,
            "enforcement_mode": ENFORCEMENT_MODE,
            "router_plane": router.status() if router else {"enabled": False},
            "last_network_sync": last_sync,
            "time": datetime.now(timezone.utc).isoformat(),
        }
        try:
            return request("POST", "/api/v1/gateway/heartbeat", {"health": health}, state)
        except PlatformError as exc:
            log("heartbeat 실패: %s", exc)
            return None

    def report_ack(payload: dict) -> None:
        """네트워크 정책 적용 결과 보고. 미지원 백엔드면 조용히 넘어간다."""
        try:
            request("POST", "/api/v1/gateway/network-policy/ack", payload, state)
        except PlatformError as exc:
            if exc.status not in {404, 405, 501}:
                raise

    def fetch(path: str) -> dict | None:
        """네트워크 정책 조회. 엔드포인트가 없으면 None(미지원)으로 처리한다."""
        try:
            return request("GET", path, None, state)
        except PlatformError as exc:
            if exc.status in {404, 405, 501}:
                return None
            raise

    while True:
        cycle_started = time.monotonic()
        try:
            heartbeat()

            # 1) 접근 정책(화이트리스트/격리) — 초 단위 운영 판단
            policy = request("GET", "/api/v1/gateway/policy", None, state)
            enforcement_report = enforcement.apply(policy)
            if policy.get("revision") != last_revision:
                last_revision = policy.get("revision")
                state["applied_policy_revision"] = last_revision
                save_state(state)
                log("접근 정책 revision %s 적용: %s", last_revision, enforcement_report)

            # 2) 네트워크 정책(desired state) — Router Plane 위임
            if router is not None:
                outcome = router.sync(fetch, heartbeat, report_ack)
                last_sync = outcome.to_health()
                if outcome.changed or outcome.stage not in {"up-to-date", "unsupported",
                                                            "idle", "no-policy"}:
                    log("네트워크 정책 동기화 [%s] revision=%s confirmed=%s %s",
                        outcome.stage, outcome.revision, outcome.confirmed,
                        outcome.message.splitlines()[0] if outcome.message else "")

            # 3) 관측 보고
            request("POST", "/api/v1/gateway/inventory", collect_inventory(), state)

        except Exception as exc:  # 한 주기의 실패가 Agent를 죽이지 않는다
            log("주기 실패: %s", exc)

        elapsed = time.monotonic() - cycle_started
        time.sleep(max(1.0, INTERVAL_SECONDS - elapsed))


if __name__ == "__main__":
    run()
