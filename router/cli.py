"""mooker-router CLI.

운영자와 Agent가 같은 코드 경로를 쓴다. 현장에서 사람이 하는 일과 중앙이 하는
일이 다른 구현을 갖게 되면, 사고는 항상 덜 쓰이는 쪽에서 난다.

    mooker-router plan    --policy p.json     # 무엇이 바뀌는지 + 사전검사
    mooker-router apply   --policy p.json     # 전체 파이프라인 실행
    mooker-router confirm                     # 자동 복구 예약 해제(확정)
    mooker-router rollback                    # 즉시 되돌리기
    mooker-router status                      # desired/applied/pending
    mooker-router verify                      # 현재 정책으로 연결 검증만
    mooker-router quarantine add --mac ...     # 즉시 격리
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from . import snapshot as snapshot_module
from .controller import NetworkController
from .dynamic import DynamicElement, DynamicStore, sync as sync_dynamic
from .envelope import TrustStore
from .errors import RouterError
from .model import RouterPolicy
from .paths import LOG_FILE, POLICY_CACHE, SNAPSHOT_DIR, TRUST_DIR
from .state import StateStore
from .util import SubprocessRunner, setup_logging
from .verify import verify as verify_policy


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _read_policy_file(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    return Path(path).read_bytes()


def _controller(args: argparse.Namespace) -> NetworkController:
    return NetworkController(
        SubprocessRunner(),
        gateway_id=args.gateway_id,
        trust=TrustStore(args.trust_dir, allow_hmac=args.allow_hmac),
        snapshot_root=args.snapshot_dir,
    )


# ---------------------------------------------------------------------------
# 서브커맨드
# ---------------------------------------------------------------------------
def cmd_plan(args) -> int:
    controller = _controller(args)
    report = controller.plan(_read_policy_file(args.policy), force=args.force)
    if args.json:
        _print_json(report.to_dict() | {"diff": report.diff})
        return 0 if report.ok else 1
    print("=== 변경 사항 (diff) ===")
    print(report.diff or "(변경 없음)")
    print("\n=== 사전검사 ===")
    print(report.message)
    if report.notes:
        print("\n=== 참고 ===")
        for note in report.notes:
            print(f"  - {note}")
    return 0 if report.ok else 1


def cmd_apply(args) -> int:
    controller = _controller(args)
    report = controller.apply(_read_policy_file(args.policy), force=args.force,
                              dry_run=args.dry_run, reason=args.reason)
    if args.json:
        _print_json(report.to_dict())
        return 0 if report.ok else 1
    print(report.summary())
    if report.rollback:
        print("\n=== 복구 결과 ===")
        _print_json(report.rollback)
    if report.stage == "pending-confirm":
        print("\n중앙이 confirm하지 않으면 자동으로 되돌아간다. "
              "수동 확정: mooker-router confirm")
    return 0 if report.ok else 1


def cmd_confirm(args) -> int:
    result = _controller(args).confirm(args.revision)
    _print_json(result) if args.json else print(result["message"])
    return 0 if result["ok"] else 1


def cmd_rollback(args) -> int:
    result = _controller(args).rollback(reason=args.reason, snapshot_id=args.snapshot)
    if args.json:
        _print_json(result)
    else:
        print(f"스냅샷 {result.get('snapshot_id')} 복구 "
              f"{'성공' if result['ok'] else '실패(부분 복구 가능)'}")
        for error in result.get("detail", {}).get("errors", []):
            print(f"  오류: {error}")
    return 0 if result["ok"] else 1


def cmd_status(args) -> int:
    status = _controller(args).status()
    if args.json:
        _print_json(status)
        return 0
    print(f"desired   : {status['desired_revision']}")
    print(f"applied   : {status['applied_revision']}")
    print(f"confirmed : {status['confirmed_revision']}")
    print(f"snapshot  : {status['last_good_snapshot']}")
    if status["pending"]:
        pending = status["pending"]
        print(f"pending   : revision {pending['revision']} — 남은 시간 "
              f"{pending['seconds_left']}s (예약 {pending['armed_unit']})")
    else:
        print("pending   : 없음")
    print(f"동적 원소 : {status['dynamic_elements']}개")
    if status["armed_rollback_units"]:
        print(f"예약된 복구: {', '.join(status['armed_rollback_units'])}")
    if status["last_error"]:
        print(f"마지막 오류: {status['last_error']}")
    return 0


def cmd_verify(args) -> int:
    path = args.policy or POLICY_CACHE
    try:
        policy = RouterPolicy.parse(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"정책을 읽을 수 없다: {path} ({exc})", file=sys.stderr)
        return 2
    report = verify_policy(policy, SubprocessRunner(), skip_delay=args.no_wait)
    if args.json:
        _print_json(report.to_dict())
    else:
        print(report.render())
    return 0 if report.ok else 1


def cmd_render(args) -> int:
    controller = _controller(args)
    try:
        policy, plan = controller.build(_read_policy_file(args.policy), force=True)
    except RouterError as exc:
        print(f"실패: {exc}", file=sys.stderr)
        return 1
    out = Path(args.out)
    for target in plan.files:
        path = out / target.path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(target.rendered(), encoding="utf-8")
        path.chmod(target.mode)
    print(f"revision {policy.revision} 렌더 결과를 {out} 아래에 기록했다 "
          f"({len(plan.files)}개 파일)")
    print(plan.describe())
    return 0


def cmd_restore_dynamic(args) -> int:
    result = sync_dynamic(SubprocessRunner(), DynamicStore())
    _print_json(result) if args.json else print(
        f"동적 셋 동기화 {'성공' if result['ok'] else '부분 실패'} (원소 {result['total']}개)")
    return 0 if result["ok"] else 1


def cmd_restore_qos(args) -> int:
    result = _controller(args).restore_qos(args.snapshot)
    _print_json(result)
    return 0


def cmd_quarantine(args) -> int:
    store = DynamicStore()
    if args.action == "list":
        elements = store.load()
        if args.json:
            _print_json([element.__dict__ for element in elements])
        else:
            if not elements:
                print("격리/차단 원소 없음")
            for element in elements:
                left = ("무기한" if element.expires_at is None
                        else f"{int(element.expires_at - time.time())}s 남음")
                print(f"{element.kind:13} {element.value:40} {left:12} {element.reason}")
        return 0

    kind = "mac" if args.mac else ("ipv4" if args.ipv4 else "ipv6")
    value = args.mac or args.ipv4 or args.ipv6
    if not value:
        print("--mac / --ipv4 / --ipv6 중 하나가 필요하다", file=sys.stderr)
        return 2
    if args.action == "add":
        element = DynamicElement(
            kind=kind, value=value, reason=args.reason, severity=args.severity,
            command_id=args.command_id,
            expires_at=(time.time() + args.ttl) if args.ttl else None,
        )
        store.upsert(element)
    else:
        store.remove(kind, value)
    result = sync_dynamic(SubprocessRunner(), store)
    if args.json:
        _print_json(result)
    else:
        print(f"{args.action} {kind} {value} → 커널 반영 "
              f"{'성공' if result['ok'] else '부분 실패'}")
    return 0 if result["ok"] else 1


def cmd_snapshots(args) -> int:
    root = Path(args.snapshot_dir)
    rows = []
    if root.is_dir():
        for path in sorted(root.iterdir()):
            if not (path / snapshot_module.MANIFEST_NAME).exists():
                continue
            manifest = snapshot_module.load(path.name, root)
            rows.append({
                "snapshot_id": manifest.snapshot_id,
                "created_at": manifest.created_at,
                "from": manifest.from_revision,
                "to": manifest.to_revision,
                "files": len(manifest.files),
                "reason": manifest.reason,
            })
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print("스냅샷 없음")
    for row in rows:
        print(f"{row['snapshot_id']:24} {row['created_at']:22} "
              f"r{row['from']}→r{row['to']:<6} 파일 {row['files']:<3} {row['reason']}")
    return 0


def cmd_selftest(args) -> int:
    """서명 → 검증 → 렌더 → 사전검사 경로를 로컬에서 한 번에 확인한다."""
    import tempfile

    from .envelope import generate_dev_keypair, sign_policy_ed25519

    sample = Path(args.policy or
                  Path(__file__).resolve().parent.parent / "examples" / "policy.sample.json")
    document = json.loads(sample.read_text(encoding="utf-8"))
    private_pem, public_raw = generate_dev_keypair()
    with tempfile.TemporaryDirectory() as tmp:
        trust_dir = Path(tmp) / "trust"
        trust_dir.mkdir()
        import base64

        (trust_dir / "selftest.ed25519").write_text(base64.b64encode(public_raw).decode())
        envelope = sign_policy_ed25519(document, private_pem, "selftest")
        controller = NetworkController(
            SubprocessRunner(),
            gateway_id=document["gateway_id"],
            trust=TrustStore(trust_dir),
            state_store=StateStore(Path(tmp) / "state.json"),
            snapshot_root=str(Path(tmp) / "snapshots"),
        )
        report = controller.plan(json.dumps(envelope))
        print("=== 서명/검증/렌더 경로 ===")
        print(f"revision {report.revision} 처리 완료")
        print(report.message)
        return 0 if report.ok else 1


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mooker-router",
        description="Mooker Gateway Router Plane — 서명된 정책을 안전하게 적용한다",
    )
    parser.add_argument("--gateway-id", default=None, help="이 장비의 gateway_id (정책 대상 검증)")
    parser.add_argument("--trust-dir", default=TRUST_DIR, help="정책 서명 공개키 디렉터리")
    parser.add_argument("--snapshot-dir", default=SNAPSHOT_DIR)
    parser.add_argument("--allow-hmac", action="store_true",
                        help="PKI 도입 전 단계에서만: HMAC 서명 키 허용")
    parser.add_argument("--json", action="store_true", help="JSON으로 출력")
    parser.add_argument("--verbose", "-v", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="변경 사항과 사전검사 결과만 확인한다")
    p.add_argument("--policy", required=True, help="서명된 정책 봉투 파일 (- 는 표준입력)")
    p.add_argument("--force", action="store_true", help="revision 되감기 검사를 생략한다")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("apply", help="전체 파이프라인을 실행한다")
    p.add_argument("--policy", required=True)
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="사전검사까지만 수행한다")
    p.add_argument("--reason", default="operator apply")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("confirm", help="적용을 확정하고 자동 복구 예약을 해제한다")
    p.add_argument("--revision", type=int, default=None)
    p.set_defaults(func=cmd_confirm)

    p = sub.add_parser("rollback", help="스냅샷으로 즉시 되돌린다")
    p.add_argument("--snapshot", default=None)
    p.add_argument("--reason", default="operator request")
    p.set_defaults(func=cmd_rollback)

    p = sub.add_parser("status", help="desired/applied/pending 상태")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("verify", help="현재 정책 기준으로 연결 검증만 수행한다")
    p.add_argument("--policy", default=None)
    p.add_argument("--no-wait", action="store_true", help="안정화 대기를 건너뛴다")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("render", help="정책을 설정 파일로 렌더해 디렉터리에 쓴다(검토용)")
    p.add_argument("--policy", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("restore-dynamic", help="검역/차단 셋 원소를 커널에 재적용한다")
    p.set_defaults(func=cmd_restore_dynamic)

    p = sub.add_parser("restore-qos", help="스냅샷의 QoS 파라미터를 재적용한다")
    p.add_argument("--snapshot", default=None)
    p.set_defaults(func=cmd_restore_qos)

    p = sub.add_parser("quarantine", help="즉시 격리/차단 원소 관리")
    p.add_argument("action", choices=["add", "remove", "list"])
    p.add_argument("--mac")
    p.add_argument("--ipv4")
    p.add_argument("--ipv6")
    p.add_argument("--ttl", type=int, default=1800, help="초 단위 만료(0=무기한)")
    p.add_argument("--reason", default="")
    p.add_argument("--severity", default="high")
    p.add_argument("--command-id", default="")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("snapshots", help="스냅샷 목록")
    p.set_defaults(func=cmd_snapshots)

    p = sub.add_parser("selftest", help="서명/검증/렌더/사전검사 경로 자체 점검")
    p.add_argument("--policy", default=None)
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, LOG_FILE)
    try:
        return args.func(args)
    except RouterError as exc:
        print(f"실패: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("중단됨", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
