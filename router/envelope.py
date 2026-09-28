"""서명된 정책 봉투 검증.

중앙 플랫폼은 정책 본문을 Ed25519로 서명해 내려보낸다. Gateway는 로컬 신뢰
저장소(/etc/mooker/trust)에 있는 공개키로만 검증하며, 검증 실패 시 정책은
파싱조차 하지 않는다. 이것이 "Agent가 네트워크 명령을 난발하지 않는다"는 계약의
첫 단계다.

봉투 형식:
    {
      "policy": { ... RouterPolicy 문서 ... },
      "signature": {
        "alg": "ed25519",
        "key_id": "mooker-policy-2026",
        "value": "<base64 서명>"
      },
      "not_before": "2026-08-27T00:00:00Z",   # 선택
      "not_after":  "2026-09-27T00:00:00Z"    # 선택
    }

서명 대상은 ``canonical_json(envelope["policy"])`` 바이트열이다. 키 정렬 + 공백
제거로 정규화하므로 전송 중 JSON 표현이 달라져도 서명이 유지된다.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import EnvelopeError
from .model import RouterPolicy
from .util import LOG, canonical_json

DEFAULT_TRUST_DIR = "/etc/mooker/trust"
ALLOWED_ALGS = {"ed25519", "hmac-sha256"}


def _parse_time(value: str, field_name: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EnvelopeError(f"{field_name} 시각 형식이 올바르지 않다: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    alg: str
    material: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.material).hexdigest()[:16]


class TrustStore:
    """파일 기반 신뢰 저장소.

    ``<trust_dir>/<key_id>.ed25519``  : base64 또는 PEM 형식 Ed25519 공개키
    ``<trust_dir>/<key_id>.hmac``     : 공유 비밀 (초기 도입/실험용, 0600)

    Ed25519를 기본으로 하고 HMAC은 PKI 도입 전 단계에서만 허용한다. HMAC 키는
    Gateway에 대칭키를 두는 방식이므로 장비 탈취 시 정책 위조가 가능하다는 점을
    운영 문서에 명시해야 한다.
    """

    def __init__(self, trust_dir: str | Path = DEFAULT_TRUST_DIR, allow_hmac: bool = False):
        self.trust_dir = Path(trust_dir)
        self.allow_hmac = allow_hmac

    def load(self, key_id: str) -> TrustedKey:
        if not key_id or "/" in key_id or ".." in key_id or len(key_id) > 128:
            raise EnvelopeError(f"key_id 형식이 올바르지 않다: {key_id!r}")
        ed_path = self.trust_dir / f"{key_id}.ed25519"
        if ed_path.exists():
            return TrustedKey(key_id, "ed25519", self._read_ed25519(ed_path))
        hmac_path = self.trust_dir / f"{key_id}.hmac"
        if hmac_path.exists():
            if not self.allow_hmac:
                raise EnvelopeError(
                    f"key_id '{key_id}'는 HMAC 키다. --allow-hmac(또는 설정)으로 명시적으로 허용해야 한다")
            self._require_private_mode(hmac_path)
            return TrustedKey(key_id, "hmac-sha256", hmac_path.read_bytes().strip())
        raise EnvelopeError(f"신뢰 저장소에 key_id '{key_id}'가 없다 ({self.trust_dir})")

    @staticmethod
    def _require_private_mode(path: Path) -> None:
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise EnvelopeError(f"비밀키 파일 권한이 너무 넓다({oct(mode)}): {path}")

    @staticmethod
    def _read_ed25519(path: Path) -> bytes:
        raw = path.read_bytes().strip()
        if raw.startswith(b"-----BEGIN"):
            return raw
        try:
            decoded = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EnvelopeError(f"Ed25519 공개키를 해석할 수 없다: {path}") from exc
        if len(decoded) != 32:
            raise EnvelopeError(f"Ed25519 공개키 길이가 32바이트가 아니다: {path}")
        return decoded


def _verify_ed25519(material: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:  # pragma: no cover - 환경 의존
        raise EnvelopeError(
            "python3-cryptography가 없어 Ed25519 서명을 검증할 수 없다. "
            "서명 검증 없이 정책을 적용하지 않는다") from exc
    try:
        if material.startswith(b"-----BEGIN"):
            public_key = load_pem_public_key(material)
            if not isinstance(public_key, Ed25519PublicKey):
                raise EnvelopeError("PEM 공개키가 Ed25519가 아니다")
        else:
            public_key = Ed25519PublicKey.from_public_bytes(material)
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError) as exc:
        raise EnvelopeError(f"공개키/서명 형식 오류: {exc}") from exc


@dataclass(frozen=True)
class VerifiedEnvelope:
    policy: RouterPolicy
    key_id: str
    alg: str
    key_fingerprint: str
    policy_digest: str
    not_before: datetime | None
    not_after: datetime | None

    def summary(self) -> dict[str, Any]:
        return {
            "revision": self.policy.revision,
            "gateway_id": self.policy.gateway_id,
            "tenant": self.policy.tenant,
            "site": self.policy.site,
            "key_id": self.key_id,
            "alg": self.alg,
            "key_fingerprint": self.key_fingerprint,
            "policy_digest": self.policy_digest,
        }


def verify_envelope(
    raw: bytes | str | dict,
    *,
    trust: TrustStore,
    expected_gateway_id: str | None = None,
    min_revision: int | None = None,
    now: datetime | None = None,
    max_size_bytes: int = 8 * 1024 * 1024,
) -> VerifiedEnvelope:
    """봉투를 검증하고 RouterPolicy를 반환한다.

    ``min_revision``을 주면 그보다 작거나 같은 revision은 거부한다(재생 공격 및
    구버전 정책 되감기 방지). 강제 재적용이 필요하면 호출자가 min_revision을
    생략하고 별도 감사 근거를 남긴다.
    """
    if isinstance(raw, (bytes, str)):
        payload = raw.encode() if isinstance(raw, str) else raw
        if len(payload) > max_size_bytes:
            raise EnvelopeError(f"정책 봉투가 너무 크다({len(payload)} bytes)")
        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EnvelopeError(f"정책 봉투 JSON 파싱 실패: {exc}") from exc
    else:
        envelope = raw
    if not isinstance(envelope, dict):
        raise EnvelopeError("정책 봉투는 JSON 객체여야 한다")

    unknown = set(envelope) - {"policy", "signature", "not_before", "not_after"}
    if unknown:
        raise EnvelopeError(f"봉투에 알 수 없는 항목: {sorted(unknown)}")

    policy_doc = envelope.get("policy")
    if not isinstance(policy_doc, dict):
        raise EnvelopeError("envelope.policy 객체가 없다")
    signature_block = envelope.get("signature")
    if not isinstance(signature_block, dict):
        raise EnvelopeError("envelope.signature 객체가 없다")

    alg = signature_block.get("alg")
    key_id = signature_block.get("key_id")
    value = signature_block.get("value")
    if alg not in ALLOWED_ALGS:
        raise EnvelopeError(f"지원하지 않는 서명 알고리즘: {alg!r}")
    if not isinstance(key_id, str) or not isinstance(value, str):
        raise EnvelopeError("signature.key_id / signature.value 형식 오류")
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EnvelopeError("signature.value가 base64가 아니다") from exc

    message = canonical_json(policy_doc)
    digest = hashlib.sha256(message).hexdigest()

    key = trust.load(key_id)
    if key.alg != alg:
        raise EnvelopeError(f"key_id '{key_id}'의 알고리즘({key.alg})과 봉투 알고리즘({alg})이 다르다")
    if alg == "ed25519":
        valid = _verify_ed25519(key.material, message, signature)
    else:
        expected = hmac.new(key.material, message, hashlib.sha256).digest()
        valid = hmac.compare_digest(expected, signature)
    if not valid:
        raise EnvelopeError(f"정책 서명 검증 실패 (key_id={key_id}, digest={digest[:16]})")

    reference = now or datetime.now(timezone.utc)
    not_before = _parse_time(envelope["not_before"], "not_before") if envelope.get("not_before") else None
    not_after = _parse_time(envelope["not_after"], "not_after") if envelope.get("not_after") else None
    if not_before and reference < not_before:
        raise EnvelopeError(f"정책 유효기간 시작 전이다 (not_before={not_before.isoformat()})")
    if not_after and reference > not_after:
        raise EnvelopeError(f"정책이 만료되었다 (not_after={not_after.isoformat()})")

    policy = RouterPolicy.parse(policy_doc)
    if expected_gateway_id and policy.gateway_id != expected_gateway_id:
        raise EnvelopeError(
            f"정책 대상 gateway_id({policy.gateway_id})가 이 장비({expected_gateway_id})와 다르다")
    if min_revision is not None and policy.revision <= min_revision:
        raise EnvelopeError(
            f"revision {policy.revision}은 이미 적용된 {min_revision} 이하다(되감기 거부)")

    LOG.info("정책 봉투 검증 완료 revision=%s key_id=%s digest=%s", policy.revision, key_id, digest[:16])
    return VerifiedEnvelope(policy, key_id, alg, key.fingerprint, digest, not_before, not_after)


# ---------------------------------------------------------------------------
# 개발/테스트 보조: 로컬 서명 (운영에서는 중앙 HSM/KMS가 담당한다)
# ---------------------------------------------------------------------------
def sign_policy_ed25519(policy_doc: dict, private_key_pem: bytes, key_id: str) -> dict:
    """테스트 및 랩 환경용 서명 헬퍼."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(canonical_json(policy_doc))
    return {
        "policy": policy_doc,
        "signature": {"alg": "ed25519", "key_id": key_id,
                      "value": base64.b64encode(signature).decode()},
    }


def generate_dev_keypair() -> tuple[bytes, bytes]:
    """(private PEM, public raw32) 쌍을 만든다. 랩 전용."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private_pem, public_raw
