"""테스트 공통 픅스처.

Router Plane은 root 권한이나 실제 커널 없이도 렌더링·검증·오케스트레이션 전체를
테스트할 수 있게 설계했다. 명령 실행은 RecordingRunner로, 파일 쓰기는 file_root로
가로챈다. 이 성질이 없으면 "적용해 보기 전에는 알 수 없는" 코드가 된다.
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

GATEWAY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GATEWAY_ROOT))

from router.context import RenderContext  # noqa: E402
from router.envelope import TrustStore, generate_dev_keypair, sign_policy_ed25519  # noqa: E402
from router.model import RouterPolicy  # noqa: E402
from router.util import RecordingRunner  # noqa: E402

SAMPLE_PATH = GATEWAY_ROOT / "examples" / "policy.sample.json"

ALL_BINARIES = {
    "nft", "netplan", "networkctl", "ip", "tc", "sysctl", "kea-dhcp4",
    "unbound-checkconf", "unbound", "wg", "wg-quick", "pppd", "systemctl",
    "systemd-run", "modprobe", "ping", "bridge", "iw", "sh",
}


@pytest.fixture
def policy_doc() -> dict:
    return copy.deepcopy(json.loads(SAMPLE_PATH.read_text(encoding="utf-8")))


@pytest.fixture
def policy(policy_doc) -> RouterPolicy:
    return RouterPolicy.parse(policy_doc)


@pytest.fixture
def ctx() -> RenderContext:
    return RenderContext(
        kea_hooks_library="/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_lease_cmds.so",
        have_cake=True,
        have_bridge_nft=True,
        unbound_supports_rpz=True,
    )


@pytest.fixture
def runner() -> RecordingRunner:
    return RecordingRunner(available=ALL_BINARIES)


@pytest.fixture
def trust(tmp_path) -> tuple[TrustStore, bytes]:
    """(신뢰 저장소, 개인키 PEM)."""
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    private_pem, public_raw = generate_dev_keypair()
    (trust_dir / "test-key.ed25519").write_text(base64.b64encode(public_raw).decode())
    return TrustStore(trust_dir), private_pem


@pytest.fixture
def make_envelope(trust):
    trust_store, private_pem = trust

    def _make(document: dict) -> dict:
        return sign_policy_ed25519(document, private_pem, "test-key")

    return _make
