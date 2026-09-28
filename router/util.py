"""공통 유틸: 명령 실행 추상화, 원자적 파일 쓰기, 최소 YAML 에미터, 검증 헬퍼.

의존성은 표준 라이브러리로 제한한다. 현장 Gateway에서 pip 설치 없이 동작해야
하고, 사전검사/렌더링 단계는 root 권한 없이도 실행되어야 한다(테스트 가능성).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol, Sequence

LOG = logging.getLogger("mooker.router")

IFNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{0,14}$")
MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,30}[a-z0-9]$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9\-_]{1,63}(\.[A-Za-z0-9\-_]{1,63})*\.?$")
SECRET_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]{0,63}$")


# --------------------------------------------------------------------------
# 명령 실행
# --------------------------------------------------------------------------
@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def summary(self, limit: int = 400) -> str:
        text = (self.stderr or self.stdout).strip().replace("\n", " ")
        return text[:limit]


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        stdin: str | None = None,
        timeout: float = 30.0,
        check: bool = False,
    ) -> CommandResult:
        ...

    def which(self, binary: str) -> str | None:
        ...


class SubprocessRunner:
    """실제 시스템에서 명령을 실행한다."""

    def __init__(self, env: dict[str, str] | None = None):
        self.env = dict(os.environ)
        self.env.setdefault("LC_ALL", "C")
        if env:
            self.env.update(env)

    def run(self, argv, stdin=None, timeout=30.0, check=False) -> CommandResult:
        argv = [str(x) for x in argv]
        started = time.monotonic()
        LOG.debug("exec %s", " ".join(argv))
        try:
            proc = subprocess.run(
                argv,
                input=stdin.encode() if stdin is not None else None,
                capture_output=True,
                timeout=timeout,
                env=self.env,
            )
            result = CommandResult(
                tuple(argv),
                proc.returncode,
                proc.stdout.decode(errors="replace"),
                proc.stderr.decode(errors="replace"),
                int((time.monotonic() - started) * 1000),
            )
        except FileNotFoundError:
            result = CommandResult(tuple(argv), 127, "", f"binary not found: {argv[0]}")
        except subprocess.TimeoutExpired:
            result = CommandResult(tuple(argv), 124, "", f"timeout after {timeout}s")
        except OSError as exc:  # pragma: no cover - 방어
            result = CommandResult(tuple(argv), 126, "", f"os error: {exc}")
        if check and not result.ok:
            raise RuntimeError(f"command failed ({result.returncode}): {' '.join(argv)}: {result.summary()}")
        return result

    def which(self, binary: str) -> str | None:
        return shutil.which(binary)


class RecordingRunner:
    """dry-run/테스트용 러너.

    명령을 실행하지 않고 기록한다. ``responses``로 특정 명령의 결과를 지정할 수
    있어 사전검사 실패 경로도 테스트할 수 있다.
    """

    def __init__(self, responses: dict[str, CommandResult] | None = None, available: Iterable[str] | None = None):
        self.calls: list[tuple[tuple[str, ...], str | None]] = []
        self.responses = responses or {}
        self._available = set(available) if available is not None else None

    def run(self, argv, stdin=None, timeout=30.0, check=False) -> CommandResult:
        argv = tuple(str(x) for x in argv)
        self.calls.append((argv, stdin))
        for key, response in self.responses.items():
            if key in " ".join(argv):
                if check and not response.ok:
                    raise RuntimeError(f"command failed: {' '.join(argv)}")
                return response
        return CommandResult(argv, 0, "", "")

    def which(self, binary: str) -> str | None:
        if self._available is None:
            return f"/usr/sbin/{binary}"
        return f"/usr/sbin/{binary}" if binary in self._available else None

    def argv_log(self) -> list[str]:
        return [" ".join(argv) for argv, _ in self.calls]


# --------------------------------------------------------------------------
# 파일 쓰기
# --------------------------------------------------------------------------
def atomic_write(path: str | Path, content: str, mode: int = 0o640, root: str | Path | None = None) -> Path:
    """같은 디렉터리 임시파일 + rename으로 원자적으로 쓴다.

    ``root``가 주어지면 staging 루트 아래로 경로를 재배치한다(사전검사용).
    """
    target = staged_path(path, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    dir_fd = os.open(str(target.parent), os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return target


def staged_path(path: str | Path, root: str | Path | None) -> Path:
    path = Path(path)
    if root is None:
        return path
    return Path(root) / path.relative_to("/") if path.is_absolute() else Path(root) / path


def iter_glob(pattern: str, root: str | Path | None = None):
    """절대 경로 패턴을 (선택적) 대체 루트 기준으로 순회한다."""
    base = Path(root) if root else Path("/")
    relative = pattern.lstrip("/")
    try:
        yield from sorted(base.glob(relative))
    except (OSError, ValueError):
        return


def read_text_or_none(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------
# 최소 YAML 에미터 (netplan 전용)
# --------------------------------------------------------------------------
_YAML_SAFE = re.compile(r"^[A-Za-z0-9_./:@+][A-Za-z0-9_./:@+\- ]*$")


def _yaml_scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or not _YAML_SAFE.match(text) or text.strip() != text:
        return json.dumps(text, ensure_ascii=False)
    if text in {"true", "false", "null", "yes", "no", "on", "off", "~"}:
        return json.dumps(text)
    return text


def yaml_dump(data: Any, indent: int = 0) -> str:
    """dict/list/스칼라만 지원하는 결정적 YAML 에미터.

    netplan 설정은 이 부분집합으로 충분하다. PyYAML 의존성을 피해 현장 설치
    표면을 줄인다. 키 순서는 입력 순서를 유지해 diff가 안정적이다.
    """
    pad = " " * indent
    lines: list[str] = []
    if isinstance(data, dict):
        if not data:
            return pad + "{}"
        for key, value in data.items():
            if isinstance(value, (dict, list)) and value:
                lines.append(f"{pad}{_yaml_scalar(key)}:")
                lines.append(yaml_dump(value, indent + 2))
            elif isinstance(value, dict):
                lines.append(f"{pad}{_yaml_scalar(key)}: {{}}")
            elif isinstance(value, list):
                lines.append(f"{pad}{_yaml_scalar(key)}: []")
            else:
                lines.append(f"{pad}{_yaml_scalar(key)}: {_yaml_scalar(value)}")
        return "\n".join(lines)
    if isinstance(data, list):
        if not data:
            return pad + "[]"
        for item in data:
            if isinstance(item, (dict, list)) and item:
                block = yaml_dump(item, indent + 2)
                first, *rest = block.split("\n")
                lines.append(f"{pad}- {first.strip()}")
                lines.extend(rest)
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return pad + _yaml_scalar(data)


# --------------------------------------------------------------------------
# 검증 헬퍼
# --------------------------------------------------------------------------
def normalize_mac(value: str) -> str:
    text = str(value).upper().replace("-", ":").strip()
    if not MAC_RE.fullmatch(text):
        raise ValueError(f"MAC 주소 형식이 아니다: {value!r}")
    return text


def check_ifname(value: str) -> str:
    if not IFNAME_RE.fullmatch(str(value)):
        raise ValueError(f"리눅스 인터페이스 이름 규칙 위반: {value!r}")
    return str(value)


def check_name(value: str) -> str:
    if not NAME_RE.fullmatch(str(value)):
        raise ValueError(f"논리 이름은 소문자/숫자/하이픈만 허용한다: {value!r}")
    return str(value)


def check_cidr(value: str, version: int | None = None) -> str:
    net = ipaddress.ip_interface(str(value))
    if version and net.version != version:
        raise ValueError(f"IPv{version} 주소가 필요하다: {value!r}")
    return str(net)


def check_network(value: str) -> str:
    net = ipaddress.ip_network(str(value), strict=True)
    return str(net)


def check_address(value: str, version: int | None = None) -> str:
    addr = ipaddress.ip_address(str(value))
    if version and addr.version != version:
        raise ValueError(f"IPv{version} 주소가 필요하다: {value!r}")
    return str(addr)


def check_port(value: int) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"포트 범위 위반: {value!r}")
    return port


def check_vlan(value: int) -> int:
    vlan = int(value)
    if not 1 <= vlan <= 4094:
        raise ValueError(f"VLAN ID는 1..4094 이다: {value!r}")
    return vlan


def check_domain(value: str) -> str:
    text = str(value).strip().lower().rstrip(".")
    if not text or not DOMAIN_RE.fullmatch(text):
        raise ValueError(f"도메인 형식이 아니다: {value!r}")
    return text


def check_secret_ref(value: str) -> str:
    if not SECRET_REF_RE.fullmatch(str(value)):
        raise ValueError(f"secret 참조 이름 규칙 위반: {value!r}")
    return str(value)


def address_in_network(address: str, network: str) -> bool:
    return ipaddress.ip_address(address) in ipaddress.ip_network(network, strict=False)


def mask_secret(value: str, keep: int = 4) -> str:
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * (len(text) - keep)


def canonical_json(data: Any) -> bytes:
    """서명 대상 정규화. 키 정렬 + 공백 제거 + UTF-8."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def setup_logging(verbose: bool = False, logfile: str | Path | None = None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if logfile:
        try:
            Path(logfile).parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(str(logfile)))
        except OSError:
            pass
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )
