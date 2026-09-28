"""QoS 렌더러 (tc + CAKE).

WAN egress에는 root qdisc로 CAKE를, ingress에는 IFB로 미러링한 뒤 CAKE를 건다.
CAKE는 bufferbloat를 잡는 데 단일 파라미터(대역폭)로 충분히 잘 동작하므로 현장
운영 부담이 작다.

tc는 설정 파일이 아니라 명령이다. 따라서 이 렌더러는 파일 대신 멱등한 명령
목록을 만들고, 실제 파라미터는 ``/run/mooker-router/qos.json``에 기록해 복구
시점에 무엇이 걸려 있었는지 알 수 있게 한다.
"""
from __future__ import annotations

import json

from ..context import RenderContext
from ..model import QosProfile, RouterPolicy
from ..paths import QOS_STATE_FILE
from ..plan import Command, FileTarget, RenderPlan


def _cake_options(profile: QosProfile, ingress: bool) -> list[str]:
    rate = profile.download_mbit if ingress else profile.upload_mbit
    options = ["bandwidth", f"{rate:g}mbit"]
    options.extend([profile.mode, "rtt", f"{profile.rtt_ms}ms"])
    if profile.nat:
        options.append("nat")
    if ingress:
        options.extend(["ingress", "wash"])
    elif profile.ack_filter:
        options.append("ack-filter")
    return options


def render(policy: RouterPolicy, ctx: RenderContext | None = None) -> RenderPlan:
    ctx = ctx or RenderContext()
    if not policy.qos:
        return RenderPlan(notes=["QoS 프로필 없음"])

    commands: list[Command] = []
    state: dict[str, dict] = {}
    notes: list[str] = []
    if not ctx.have_cake:
        notes.append(
            "sch_cake 모듈을 확인하지 못했다. CAKE가 없으면 fq_codel로 대체되며 상한 제어 "
            "정확도가 떨어진다. `apt install linux-modules-extra-$(uname -r)`를 확인한다.")

    commands.append(Command(("modprobe", "sch_cake"), description="CAKE 모듈", allow_fail=True))
    commands.append(Command(("modprobe", "ifb"), description="IFB 모듈", allow_fail=True))

    for profile in policy.qos:
        link = policy.wan(profile.wan)
        device = link.link_interface
        if not profile.enabled:
            commands.append(Command(("tc", "qdisc", "del", "dev", device, "root"),
                                    description=f"{profile.wan} QoS 해제", allow_fail=True))
            commands.append(Command(("tc", "qdisc", "del", "dev", device, "ingress"),
                                    description=f"{profile.wan} ingress 해제", allow_fail=True))
            state[profile.wan] = {"enabled": False, "device": device}
            continue

        qdisc = "cake" if ctx.have_cake else "fq_codel"
        egress = ["tc", "qdisc", "replace", "dev", device, "root", qdisc]
        if ctx.have_cake:
            egress.extend(_cake_options(profile, ingress=False))
        commands.append(Command(tuple(egress), description=f"{profile.wan} egress shaping",
                                timeout=20.0))

        if profile.ingress_shaping:
            ifb = profile.ifb_device
            commands.extend([
                Command(("sh", "-c", f"ip link show {ifb} >/dev/null 2>&1 || "
                                     f"ip link add name {ifb} type ifb"),
                        description=f"{ifb} 생성", timeout=15.0),
                Command(("ip", "link", "set", "dev", ifb, "up"), description=f"{ifb} up",
                        timeout=15.0),
                Command(("tc", "qdisc", "replace", "dev", device, "handle", "ffff:", "ingress"),
                        description=f"{device} ingress qdisc", timeout=15.0, allow_fail=True),
                Command(("sh", "-c",
                         f"tc filter replace dev {device} parent ffff: protocol all prio 10 "
                         f"u32 match u32 0 0 flowid 1:1 action mirred egress redirect dev {ifb}"),
                        description=f"{device} -> {ifb} 미러링", timeout=15.0),
            ])
            ingress_cmd = ["tc", "qdisc", "replace", "dev", ifb, "root", qdisc]
            if ctx.have_cake:
                ingress_cmd.extend(_cake_options(profile, ingress=True))
            commands.append(Command(tuple(ingress_cmd),
                                    description=f"{profile.wan} ingress shaping", timeout=20.0))
        state[profile.wan] = {
            "enabled": True,
            "device": device,
            "qdisc": qdisc,
            "upload_mbit": profile.upload_mbit,
            "download_mbit": profile.download_mbit,
            "ifb": profile.ifb_device if profile.ingress_shaping else None,
        }

    return RenderPlan(
        files=[FileTarget(QOS_STATE_FILE, json.dumps(state, indent=2) + "\n", 0o644,
                          "적용된 QoS 파라미터 (런타임 참조용)", persistent=False)],
        apply_commands=commands,
        notes=notes,
        required_binaries=["tc", "ip"],
    )
