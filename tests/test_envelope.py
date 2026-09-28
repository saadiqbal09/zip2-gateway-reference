"""서명 봉투 검증 테스트.

정책 적용의 첫 관문이다. 여기가 뚫리면 나머지 안전장치는 의미가 없다.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from router.envelope import TrustStore, generate_dev_keypair, sign_policy_ed25519, verify_envelope
from router.errors import EnvelopeError


def test_valid_envelope_verifies(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    verified = verify_envelope(json.dumps(make_envelope(policy_doc)), trust=trust_store)
    assert verified.policy.revision == 42
    assert verified.key_id == "test-key"
    assert len(verified.policy_digest) == 64


def test_tampered_policy_rejected(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    envelope["policy"]["firewall"]["mgmt_allow_cidrs"] = ["0.0.0.0/0"]
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(envelope), trust=trust_store)
    assert "서명 검증 실패" in str(info.value)


def test_key_reordering_does_not_break_signature(policy_doc, trust, make_envelope):
    """정규화(키 정렬)를 하므로 전송 중 JSON 표현이 바뀌어도 서명이 유지된다."""
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    reordered = json.loads(json.dumps(envelope, sort_keys=True))
    reordered["policy"] = dict(reversed(list(reordered["policy"].items())))
    assert verify_envelope(json.dumps(reordered), trust=trust_store).policy.revision == 42


def test_unknown_key_id_rejected(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    envelope["signature"]["key_id"] = "attacker-key"
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(envelope), trust=trust_store)
    assert "신뢰 저장소에" in str(info.value)


def test_other_key_signature_rejected(policy_doc, trust):
    """다른 키로 서명한 봉투는, key_id가 맞아도 통과하지 못한다."""
    trust_store, _ = trust
    other_private, _ = generate_dev_keypair()
    envelope = sign_policy_ed25519(policy_doc, other_private, "test-key")
    with pytest.raises(EnvelopeError):
        verify_envelope(json.dumps(envelope), trust=trust_store)


def test_wrong_gateway_rejected(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(make_envelope(policy_doc)), trust=trust_store,
                        expected_gateway_id="another-gateway")
    assert "이 장비" in str(info.value)


def test_revision_rollback_rejected(policy_doc, trust, make_envelope):
    """구버전 정책 재전송(되감기)을 막는다."""
    trust_store, _ = trust
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(make_envelope(policy_doc)), trust=trust_store,
                        min_revision=42)
    assert "되감기 거부" in str(info.value)


def test_expiry_enforced(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    envelope["not_after"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(envelope), trust=trust_store)
    assert "만료" in str(info.value)


def test_not_before_enforced(policy_doc, trust, make_envelope):
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    envelope["not_before"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    with pytest.raises(EnvelopeError):
        verify_envelope(json.dumps(envelope), trust=trust_store)


def test_unknown_envelope_field_rejected(policy_doc, trust, make_envelope):
    """서명 대상 밖의 필드를 봉투에 끼워 넣을 수 없다."""
    trust_store, _ = trust
    envelope = make_envelope(policy_doc)
    envelope["enforcement"] = {"quarantine": []}
    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(envelope), trust=trust_store)
    assert "알 수 없는 항목" in str(info.value)


def test_hmac_requires_explicit_optin(policy_doc, tmp_path):
    import hashlib
    import hmac

    from router.util import canonical_json

    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    secret = b"shared-secret-for-lab-only"
    key_file = trust_dir / "lab.hmac"
    key_file.write_bytes(secret)
    key_file.chmod(0o600)
    signature = hmac.new(secret, canonical_json(policy_doc), hashlib.sha256).digest()
    envelope = {"policy": policy_doc,
                "signature": {"alg": "hmac-sha256", "key_id": "lab",
                              "value": base64.b64encode(signature).decode()}}

    with pytest.raises(EnvelopeError) as info:
        verify_envelope(json.dumps(envelope), trust=TrustStore(trust_dir))
    assert "명시적으로 허용" in str(info.value)

    verified = verify_envelope(json.dumps(envelope),
                               trust=TrustStore(trust_dir, allow_hmac=True))
    assert verified.alg == "hmac-sha256"


def test_hmac_key_with_loose_permissions_rejected(policy_doc, tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    key_file = trust_dir / "lab.hmac"
    key_file.write_bytes(b"secret")
    key_file.chmod(0o644)
    with pytest.raises(EnvelopeError) as info:
        TrustStore(trust_dir, allow_hmac=True).load("lab")
    assert "권한이 너무 넓다" in str(info.value)


def test_path_traversal_in_key_id_rejected(tmp_path):
    with pytest.raises(EnvelopeError):
        TrustStore(tmp_path).load("../../etc/shadow")
