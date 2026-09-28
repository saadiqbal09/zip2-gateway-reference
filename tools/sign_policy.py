#!/usr/bin/env python3
"""정책 서명 도구 (랩·초기 도입용).

운영에서는 중앙 플랫폼의 HSM/KMS가 이 역할을 해야 한다. 개인키가 사람의 노트북이나
서버 디스크에 평문으로 있는 한, 그 키를 가진 누구든 모든 Gateway의 네트워크를
바꿀 수 있다. 이 스크립트는 그 파이프라인이 생기기 전까지의 도구다.

사용법

  # 1) 키쌍 생성 (한 번만). 개인키는 중앙에, 공개키는 각 Gateway에 배포한다.
  python3 tools/sign_policy.py keygen --key-id mooker-policy-2026 --out ./keys

  # 2) 공개키를 Gateway 신뢰 저장소에 배치
  scp keys/mooker-policy-2026.ed25519 gw:/tmp/
  ssh gw 'sudo install -m 0644 /tmp/mooker-policy-2026.ed25519 /etc/mooker/trust/'

  # 3) 정책 문서(JSON 또는 YAML)에 서명해 봉투를 만든다
  python3 tools/sign_policy.py sign \
      --policy examples/policy.sample.json \
      --key keys/mooker-policy-2026.key \
      --key-id mooker-policy-2026 \
      --out /tmp/policy.signed.json

  # 4) 서명이 유효한지 배포 전에 확인
  python3 tools/sign_policy.py check \
      --envelope /tmp/policy.signed.json --trust-dir keys
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from router.envelope import (  # noqa: E402
    TrustStore,
    generate_dev_keypair,
    sign_policy_ed25519,
    verify_envelope,
)
from router.model import RouterPolicy  # noqa: E402


def load_document(path: str) -> dict:
    """JSON을 우선 시도하고, 실패하면 YAML로 읽는다."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
        except ImportError:
            raise SystemExit(
                f"{path}를 JSON으로 읽지 못했다. YAML이라면 PyYAML이 필요하다: "
                f"apt install python3-yaml")
        document = yaml.safe_load(text)
        if not isinstance(document, dict):
            raise SystemExit(f"{path}가 정책 객체가 아니다")
        return document


def cmd_keygen(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    private_path = out / f"{args.key_id}.key"
    public_path = out / f"{args.key_id}.ed25519"
    if private_path.exists() and not args.force:
        raise SystemExit(f"이미 존재한다: {private_path} (덮어쓰려면 --force)")

    private_pem, public_raw = generate_dev_keypair()
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)
    public_path.write_text(base64.b64encode(public_raw).decode() + "\n")
    public_path.chmod(0o644)

    print(f"개인키(중앙에만 보관, 0600): {private_path}")
    print(f"공개키(각 Gateway에 배포): {public_path}")
    print()
    print("Gateway 배포:")
    print(f"  sudo install -m 0644 {public_path} /etc/mooker/trust/")
    print()
    print("주의: 이 개인키를 가진 누구든 모든 Gateway의 네트워크를 바꿀 수 있다.")
    print("      운영 전환 시 HSM/KMS로 옮기고 이 파일은 폐기한다.")
    return 0


def cmd_sign(args) -> int:
    document = load_document(args.policy)

    if args.gateway_id:
        document["gateway_id"] = args.gateway_id
    if args.revision is not None:
        document["revision"] = args.revision
    if args.bump:
        document["revision"] = int(document.get("revision", 0)) + 1
    document["generated_at"] = datetime.now(timezone.utc).replace(
        microsecond=0).isoformat().replace("+00:00", "Z")

    # 서명 전에 현장과 동일한 검증을 돌린다. 여기서 잡히는 오류를 장비까지
    # 보내면, 거부는 되지만 왕복 시간과 감사 로그만 낭비된다.
    try:
        policy = RouterPolicy.parse(document)
    except Exception as exc:
        print(f"정책 검증 실패 — 서명하지 않는다:\n  {exc}", file=sys.stderr)
        return 1

    envelope = sign_policy_ed25519(document, Path(args.key).read_bytes(), args.key_id)
    if args.valid_days:
        now = datetime.now(timezone.utc)
        envelope["not_before"] = now.replace(microsecond=0).isoformat()
        envelope["not_after"] = (now + timedelta(days=args.valid_days)).replace(
            microsecond=0).isoformat()

    output = json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"
    if args.out == "-":
        sys.stdout.write(output)
    else:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"서명 완료: {args.out}")
    print(f"  gateway_id : {policy.gateway_id}")
    print(f"  revision   : {policy.revision}  (반드시 이전보다 커야 적용된다)")
    print(f"  site/tenant: {policy.site} / {policy.tenant}")
    print(f"  key_id     : {args.key_id}")
    return 0


def cmd_check(args) -> int:
    raw = Path(args.envelope).read_bytes()
    try:
        verified = verify_envelope(
            raw, trust=TrustStore(args.trust_dir, allow_hmac=args.allow_hmac),
            expected_gateway_id=args.gateway_id)
    except Exception as exc:
        print(f"검증 실패: {exc}", file=sys.stderr)
        return 1
    print("검증 통과")
    for key, value in verified.summary().items():
        print(f"  {key:16}: {value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sign_policy.py",
        description="정책 문서에 서명해 Gateway가 받아들이는 봉투를 만든다",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="Ed25519 키쌍 생성")
    p.add_argument("--key-id", required=True, help="예: mooker-policy-2026")
    p.add_argument("--out", default="./keys")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="정책에 서명")
    p.add_argument("--policy", required=True, help="정책 JSON 또는 YAML")
    p.add_argument("--key", required=True, help="개인키 PEM 경로")
    p.add_argument("--key-id", required=True, help="Gateway 신뢰 저장소의 키 이름과 일치해야 한다")
    p.add_argument("--out", default="-", help="출력 파일 (기본: 표준출력)")
    p.add_argument("--gateway-id", default=None, help="정책의 gateway_id를 덮어쓴다")
    p.add_argument("--revision", type=int, default=None)
    p.add_argument("--bump", action="store_true", help="revision을 1 올린다")
    p.add_argument("--valid-days", type=int, default=None,
                   help="봉투 유효기간(일). 지정하면 not_before/not_after를 넣는다")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("check", help="봉투 검증 (배포 전 확인)")
    p.add_argument("--envelope", required=True)
    p.add_argument("--trust-dir", default="./keys")
    p.add_argument("--gateway-id", default=None)
    p.add_argument("--allow-hmac", action="store_true")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
