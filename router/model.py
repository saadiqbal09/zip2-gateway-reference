"""선언형 네트워크 정책 모델 (desired state).

중앙 플랫폼이 보내는 것은 "명령"이 아니라 "이 Gateway가 최종적으로 어떤
상태여야 하는가"이다. 이 모듈은 그 문서를 강타입 객체로 파싱하고, 렌더링
이전에 의미 수준까지 검증한다. 검증을 통과하지 못한 정책은 시스템에 닿지
않는다.

설계 원칙
- 비밀값은 정책에 넣지 않는다. ``*_ref`` 필드로 로컬 secret 저장소를 참조한다.
- 검증은 fail-closed. 모르는 필드는 거부하고, 모호한 값은 거부한다.
- 보안 baseline(관리 접근/제어 채널 보호)은 하위 정책이 완화할 수 없다.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import BaselineViolation, PolicyError
from .util import (
    address_in_network,
    check_address,
    check_cidr,
    check_domain,
    check_ifname,
    check_name,
    check_network,
    check_port,
    check_secret_ref,
    check_vlan,
    normalize_mac,
)

SCHEMA_VERSION = 1

# ---------------------------------------------------------------------------
# dict 리더: 경로를 추적하며 타입 강제 + 미지 필드 거부
# ---------------------------------------------------------------------------


class Reader:
    def __init__(self, data: Any, path: str = "policy"):
        if not isinstance(data, dict):
            raise PolicyError("객체(mapping)가 필요하다", path)
        self.data = dict(data)
        self.path = path
        self._seen: set[str] = set()

    def _at(self, key: str) -> str:
        return f"{self.path}.{key}"

    def _get(self, key: str, default: Any, required: bool) -> Any:
        self._seen.add(key)
        if key in self.data and self.data[key] is not None:
            return self.data[key]
        if required:
            raise PolicyError("필수 항목이 없다", self._at(key))
        return default

    def wrap(self, key: str, value: Any, func) -> Any:
        try:
            return func(value)
        except (ValueError, TypeError) as exc:
            raise PolicyError(str(exc), self._at(key)) from exc

    def str_(self, key: str, default: str | None = None, required: bool = False, choices: Iterable[str] | None = None,
             max_length: int = 512) -> Any:
        value = self._get(key, default, required)
        if value is None:
            return None
        if not isinstance(value, str):
            raise PolicyError("문자열이어야 한다", self._at(key))
        if len(value) > max_length:
            raise PolicyError(f"길이 {max_length} 초과", self._at(key))
        if choices is not None and value not in choices:
            raise PolicyError(f"허용값: {sorted(choices)}", self._at(key))
        return value

    def int_(self, key: str, default: int | None = None, required: bool = False,
             minimum: int | None = None, maximum: int | None = None) -> Any:
        value = self._get(key, default, required)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise PolicyError("정수여야 한다", self._at(key))
        if minimum is not None and value < minimum:
            raise PolicyError(f"{minimum} 이상이어야 한다", self._at(key))
        if maximum is not None and value > maximum:
            raise PolicyError(f"{maximum} 이하여야 한다", self._at(key))
        return value

    def float_(self, key: str, default: float | None = None, minimum: float | None = None,
               maximum: float | None = None) -> Any:
        value = self._get(key, default, False)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise PolicyError("숫자여야 한다", self._at(key))
        value = float(value)
        if minimum is not None and value < minimum:
            raise PolicyError(f"{minimum} 이상이어야 한다", self._at(key))
        if maximum is not None and value > maximum:
            raise PolicyError(f"{maximum} 이하여야 한다", self._at(key))
        return value

    def bool_(self, key: str, default: bool = False) -> bool:
        value = self._get(key, default, False)
        if not isinstance(value, bool):
            raise PolicyError("true/false 여야 한다", self._at(key))
        return value

    def list_(self, key: str, max_items: int = 512) -> list:
        value = self._get(key, [], False)
        if not isinstance(value, list):
            raise PolicyError("배열이어야 한다", self._at(key))
        if len(value) > max_items:
            raise PolicyError(f"항목 {max_items}개 초과", self._at(key))
        return value

    def str_list(self, key: str, func=None, max_items: int = 512) -> list[str]:
        out = []
        for index, item in enumerate(self.list_(key, max_items)):
            if not isinstance(item, str):
                raise PolicyError("문자열 배열이어야 한다", f"{self._at(key)}[{index}]")
            if func is None:
                out.append(item)
            else:
                try:
                    out.append(func(item))
                except (ValueError, TypeError) as exc:
                    raise PolicyError(str(exc), f"{self._at(key)}[{index}]") from exc
        return out

    def int_list(self, key: str, func=None, max_items: int = 512) -> list[int]:
        out = []
        for index, item in enumerate(self.list_(key, max_items)):
            if isinstance(item, bool) or not isinstance(item, int):
                raise PolicyError("정수 배열이어야 한다", f"{self._at(key)}[{index}]")
            if func is None:
                out.append(item)
            else:
                try:
                    out.append(func(item))
                except (ValueError, TypeError) as exc:
                    raise PolicyError(str(exc), f"{self._at(key)}[{index}]") from exc
        return out

    def obj(self, key: str, required: bool = False) -> "Reader | None":
        value = self._get(key, None, required)
        if value is None:
            return None
        return Reader(value, self._at(key))

    def objs(self, key: str, max_items: int = 512) -> list["Reader"]:
        out = []
        for index, item in enumerate(self.list_(key, max_items)):
            out.append(Reader(item, f"{self._at(key)}[{index}]"))
        return out

    def dict_(self, key: str) -> dict:
        value = self._get(key, {}, False)
        if not isinstance(value, dict):
            raise PolicyError("객체여야 한다", self._at(key))
        return dict(value)

    def done(self) -> None:
        """정의되지 않은 키를 거부한다(fail-closed).

        중앙이 신규 필드를 보냈는데 이 Agent가 모르면, 조용히 무시하는 것보다
        거부하는 것이 안전하다. OTA로 Agent를 먼저 올린 뒤 정책을 배포한다.
        """
        unknown = sorted(set(self.data) - self._seen)
        if unknown:
            raise PolicyError(f"알 수 없는 항목: {unknown} (Agent 버전 확인 필요)", self.path)


# ---------------------------------------------------------------------------
# 구성 요소
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Probe:
    """회선 품질/생존 확인 대상."""

    kind: str  # icmp | tcp | dns | https
    target: str
    port: int | None = None
    hostname: str | None = None
    timeout_s: float = 3.0

    @staticmethod
    def parse(r: Reader) -> "Probe":
        kind = r.str_("kind", required=True, choices={"icmp", "tcp", "dns", "https"})
        target = r.str_("target", required=True)
        port = r.int_("port", None, minimum=1, maximum=65535)
        hostname = r.str_("hostname", None)
        timeout = r.float_("timeout_s", 3.0, minimum=0.5, maximum=30.0)
        r.done()
        if kind in {"icmp", "tcp", "dns"}:
            r.wrap("target", target, check_address)
        if kind == "tcp" and port is None:
            raise PolicyError("tcp probe는 port가 필요하다", r.path)
        if kind == "dns" and not hostname:
            raise PolicyError("dns probe는 조회할 hostname이 필요하다", r.path)
        if kind == "https" and not hostname:
            raise PolicyError("https probe는 hostname이 필요하다", r.path)
        return Probe(kind, target, port, hostname, timeout)


@dataclass(frozen=True)
class PppoeSpec:
    username: str
    password_ref: str
    service: str | None = None
    access_concentrator: str | None = None
    mtu: int = 1492
    lcp_echo_interval: int = 10
    lcp_echo_failure: int = 5

    @staticmethod
    def parse(r: Reader) -> "PppoeSpec":
        spec = PppoeSpec(
            username=r.str_("username", required=True, max_length=128),
            password_ref=r.wrap("password_ref", r.str_("password_ref", required=True), check_secret_ref),
            service=r.str_("service", None, max_length=64),
            access_concentrator=r.str_("access_concentrator", None, max_length=64),
            mtu=r.int_("mtu", 1492, minimum=576, maximum=1500),
            lcp_echo_interval=r.int_("lcp_echo_interval", 10, minimum=0, maximum=600),
            lcp_echo_failure=r.int_("lcp_echo_failure", 5, minimum=0, maximum=100),
        )
        r.done()
        return spec


@dataclass(frozen=True)
class WanLink:
    name: str
    interface: str
    mode: str  # dhcp4 | static | pppoe
    addresses: tuple[str, ...] = ()
    gateway4: str | None = None
    gateway6: str | None = None
    nameservers: tuple[str, ...] = ()
    accept_ra: bool = False
    mtu: int | None = None
    metric: int = 100
    table: int | None = None
    weight: int = 1
    pppoe: PppoeSpec | None = None
    probes: tuple[Probe, ...] = ()
    required_for_online: bool = True

    @property
    def link_interface(self) -> str:
        """L3가 올라오는 인터페이스. PPPoE는 ppp 디바이스가 된다."""
        return f"ppp-{self.name}" if self.mode == "pppoe" else self.interface

    @staticmethod
    def parse(r: Reader) -> "WanLink":
        name = r.wrap("name", r.str_("name", required=True), check_name)
        interface = r.wrap("interface", r.str_("interface", required=True), check_ifname)
        mode = r.str_("mode", required=True, choices={"dhcp4", "static", "pppoe"})
        addresses = tuple(r.str_list("addresses", check_cidr, max_items=8))
        gateway4 = r.str_("gateway4", None)
        gateway6 = r.str_("gateway6", None)
        nameservers = tuple(r.str_list("nameservers", check_address, max_items=8))
        accept_ra = r.bool_("accept_ra", False)
        mtu = r.int_("mtu", None, minimum=576, maximum=9000)
        metric = r.int_("metric", 100, minimum=1, maximum=4294967295)
        table = r.int_("table", None, minimum=1, maximum=252)
        weight = r.int_("weight", 1, minimum=1, maximum=256)
        pppoe_reader = r.obj("pppoe")
        probes = tuple(Probe.parse(p) for p in r.objs("probes", max_items=8))
        required = r.bool_("required_for_online", True)
        r.done()

        if gateway4:
            gateway4 = r.wrap("gateway4", gateway4, lambda v: check_address(v, 4))
        if gateway6:
            gateway6 = r.wrap("gateway6", gateway6, lambda v: check_address(v, 6))
        if mode == "static":
            if not addresses:
                raise PolicyError("static WAN은 addresses가 필요하다", r.path)
            if not gateway4 and not gateway6:
                raise PolicyError("static WAN은 gateway4 또는 gateway6가 필요하다", r.path)
        if mode == "pppoe" and pppoe_reader is None:
            raise PolicyError("pppoe 모드는 pppoe 블록이 필요하다", r.path)
        if mode != "pppoe" and pppoe_reader is not None:
            raise PolicyError("pppoe 블록은 mode=pppoe 에서만 쓴다", r.path)
        if mode == "dhcp4" and addresses:
            raise PolicyError("dhcp4 모드에는 static addresses를 함께 줄 수 없다", r.path)
        return WanLink(
            name=name,
            interface=interface,
            mode=mode,
            addresses=addresses,
            gateway4=gateway4,
            gateway6=gateway6,
            nameservers=nameservers,
            accept_ra=accept_ra,
            mtu=mtu,
            metric=metric,
            table=table,
            weight=weight,
            pppoe=PppoeSpec.parse(pppoe_reader) if pppoe_reader else None,
            probes=probes,
            required_for_online=required,
        )


@dataclass(frozen=True)
class BridgeSpec:
    name: str
    ports: tuple[str, ...]
    vlan_filtering: bool = False
    default_pvid: int = 1
    stp: bool = False
    isolated_ports: tuple[str, ...] = ()
    trunk_ports: tuple[str, ...] = ()
    drop_rogue_dhcp: bool = True

    @staticmethod
    def parse(r: Reader) -> "BridgeSpec":
        name = r.wrap("name", r.str_("name", required=True), check_ifname)
        ports = tuple(r.str_list("ports", check_ifname, max_items=64))
        vlan_filtering = r.bool_("vlan_filtering", False)
        default_pvid = r.wrap("default_pvid", r.int_("default_pvid", 1), check_vlan)
        stp = r.bool_("stp", False)
        isolated = tuple(r.str_list("isolated_ports", check_ifname, max_items=64))
        trunk = tuple(r.str_list("trunk_ports", check_ifname, max_items=64))
        drop_rogue_dhcp = r.bool_("drop_rogue_dhcp", True)
        r.done()
        if not ports:
            raise PolicyError("bridge는 최소 1개 port가 필요하다", r.path)
        if len(set(ports)) != len(ports):
            raise PolicyError("중복된 bridge port", r.path)
        unknown = set(isolated) - set(ports)
        if unknown:
            raise PolicyError(f"isolated_ports가 ports에 없다: {sorted(unknown)}", r.path)
        unknown = set(trunk) - set(ports)
        if unknown:
            raise PolicyError(f"trunk_ports가 ports에 없다: {sorted(unknown)}", r.path)
        if trunk and not vlan_filtering:
            raise PolicyError("trunk_ports는 vlan_filtering=true 에서만 의미가 있다", r.path)
        return BridgeSpec(name, ports, vlan_filtering, default_pvid, stp, isolated, trunk, drop_rogue_dhcp)


@dataclass(frozen=True)
class Reservation:
    mac: str
    ip: str
    hostname: str | None = None

    @staticmethod
    def parse(r: Reader) -> "Reservation":
        mac = r.wrap("mac", r.str_("mac", required=True), normalize_mac)
        ip = r.wrap("ip", r.str_("ip", required=True), lambda v: check_address(v, 4))
        hostname = r.str_("hostname", None, max_length=64)
        r.done()
        return Reservation(mac, ip, hostname)


@dataclass(frozen=True)
class DhcpScope:
    subnet: str
    pool_start: str
    pool_end: str
    routers: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    domain_name: str | None = None
    lease_lifetime_s: int = 3600
    ntp_servers: tuple[str, ...] = ()
    reservations: tuple[Reservation, ...] = ()
    unknown_clients_allowed: bool = True

    @staticmethod
    def parse(r: Reader) -> "DhcpScope":
        subnet = r.wrap("subnet", r.str_("subnet", required=True), check_network)
        pool_start = r.wrap("pool_start", r.str_("pool_start", required=True), lambda v: check_address(v, 4))
        pool_end = r.wrap("pool_end", r.str_("pool_end", required=True), lambda v: check_address(v, 4))
        routers = tuple(r.str_list("routers", lambda v: check_address(v, 4), max_items=4))
        dns = tuple(r.str_list("dns", lambda v: check_address(v, 4), max_items=4))
        domain_name = r.str_("domain_name", None)
        lease = r.int_("lease_lifetime_s", 3600, minimum=120, maximum=604800)
        ntp = tuple(r.str_list("ntp_servers", lambda v: check_address(v, 4), max_items=4))
        reservations = tuple(Reservation.parse(x) for x in r.objs("reservations", max_items=4096))
        unknown_allowed = r.bool_("unknown_clients_allowed", True)
        r.done()

        if domain_name:
            domain_name = r.wrap("domain_name", domain_name, check_domain)
        network = ipaddress.ip_network(subnet)
        if network.version != 4:
            raise PolicyError("DHCPv4 scope는 IPv4 subnet이어야 한다", r.path)
        start, end = ipaddress.ip_address(pool_start), ipaddress.ip_address(pool_end)
        if start not in network or end not in network:
            raise PolicyError("pool 범위가 subnet 밖이다", r.path)
        if start > end:
            raise PolicyError("pool_start가 pool_end보다 크다", r.path)
        seen_mac: set[str] = set()
        seen_ip: set[str] = set()
        for res in reservations:
            if res.mac in seen_mac:
                raise PolicyError(f"중복 reservation MAC: {res.mac}", r.path)
            if res.ip in seen_ip:
                raise PolicyError(f"중복 reservation IP: {res.ip}", r.path)
            if not address_in_network(res.ip, subnet):
                raise PolicyError(f"reservation IP가 subnet 밖이다: {res.ip}", r.path)
            if start <= ipaddress.ip_address(res.ip) <= end:
                raise PolicyError(f"reservation IP가 동적 pool과 겹친다: {res.ip}", r.path)
            seen_mac.add(res.mac)
            seen_ip.add(res.ip)
        return DhcpScope(subnet, pool_start, pool_end, routers, dns, domain_name, lease, ntp,
                         reservations, unknown_allowed)


@dataclass(frozen=True)
class LanSegment:
    name: str
    interface: str
    zone: str
    addresses: tuple[str, ...] = ()
    vlan_id: int | None = None
    vlan_link: str | None = None
    vrf: str | None = None
    mtu: int | None = None
    client_isolation: bool = False
    untagged_ports: tuple[str, ...] = ()
    dhcp: DhcpScope | None = None
    ipv6_ra: bool = False
    description: str = ""

    @property
    def device(self) -> str:
        return self.interface

    @property
    def gateway_ipv4(self) -> str | None:
        for cidr in self.addresses:
            iface = ipaddress.ip_interface(cidr)
            if iface.version == 4:
                return str(iface.ip)
        return None

    @staticmethod
    def parse(r: Reader) -> "LanSegment":
        name = r.wrap("name", r.str_("name", required=True), check_name)
        interface = r.wrap("interface", r.str_("interface", required=True), check_ifname)
        zone = r.wrap("zone", r.str_("zone", required=True), check_name)
        addresses = tuple(r.str_list("addresses", check_cidr, max_items=8))
        vlan_id = r.int_("vlan_id", None, minimum=1, maximum=4094)
        vlan_link = r.str_("vlan_link", None)
        vrf = r.str_("vrf", None)
        mtu = r.int_("mtu", None, minimum=576, maximum=9000)
        client_isolation = r.bool_("client_isolation", False)
        untagged_ports = tuple(r.str_list("untagged_ports", check_ifname, max_items=64))
        dhcp_reader = r.obj("dhcp")
        ipv6_ra = r.bool_("ipv6_ra", False)
        description = r.str_("description", "", max_length=256)
        r.done()

        if vlan_link:
            vlan_link = r.wrap("vlan_link", vlan_link, check_ifname)
        if vlan_id is not None and not vlan_link:
            raise PolicyError("vlan_id를 쓰면 vlan_link(상위 bridge/NIC)가 필요하다", r.path)
        if not addresses:
            raise PolicyError("LAN segment는 최소 1개 주소가 필요하다", r.path)
        dhcp = DhcpScope.parse(dhcp_reader) if dhcp_reader else None
        if dhcp:
            ipv4 = None
            for cidr in addresses:
                iface = ipaddress.ip_interface(cidr)
                if iface.version == 4:
                    ipv4 = iface
                    break
            if ipv4 is None:
                raise PolicyError("DHCP를 쓰는 segment는 IPv4 주소가 필요하다", r.path)
            if str(ipv4.network) != dhcp.subnet:
                raise PolicyError(
                    f"DHCP subnet({dhcp.subnet})이 segment 주소({ipv4})의 네트워크와 다르다", r.path
                )
            if address_in_network(str(ipv4.ip), dhcp.subnet) and (
                ipaddress.ip_address(dhcp.pool_start) <= ipv4.ip <= ipaddress.ip_address(dhcp.pool_end)
            ):
                raise PolicyError("Gateway 주소가 DHCP pool 안에 있다", r.path)
        if untagged_ports and vlan_id is None:
            raise PolicyError("untagged_ports는 VLAN segment에서만 쓴다", r.path)
        return LanSegment(name, interface, zone, addresses, vlan_id, vlan_link, vrf, mtu,
                          client_isolation, untagged_ports, dhcp, ipv6_ra, description)


@dataclass(frozen=True)
class VrfSpec:
    name: str
    table: int
    interfaces: tuple[str, ...] = ()

    @staticmethod
    def parse(r: Reader) -> "VrfSpec":
        name = r.wrap("name", r.str_("name", required=True), check_ifname)
        table = r.int_("table", required=True, minimum=2, maximum=4294967295)
        interfaces = tuple(r.str_list("interfaces", check_ifname, max_items=64))
        r.done()
        return VrfSpec(name, table, interfaces)


@dataclass(frozen=True)
class PortForward:
    name: str
    wan: str
    protocol: str
    wan_port: int
    to_address: str
    to_port: int
    source_cidrs: tuple[str, ...] = ()

    @staticmethod
    def parse(r: Reader) -> "PortForward":
        name = r.wrap("name", r.str_("name", required=True), check_name)
        wan = r.wrap("wan", r.str_("wan", required=True), check_name)
        protocol = r.str_("protocol", required=True, choices={"tcp", "udp"})
        wan_port = r.wrap("wan_port", r.int_("wan_port", required=True), check_port)
        to_address = r.wrap("to_address", r.str_("to_address", required=True), check_address)
        to_port = r.wrap("to_port", r.int_("to_port", required=True), check_port)
        source_cidrs = tuple(r.str_list("source_cidrs", check_network, max_items=32))
        r.done()
        return PortForward(name, wan, protocol, wan_port, to_address, to_port, source_cidrs)


@dataclass(frozen=True)
class ServiceAllow:
    """zone에서 Gateway 자신(input hook)으로 허용할 서비스."""

    zone: str
    protocol: str
    ports: tuple[int, ...]
    source_cidrs: tuple[str, ...] = ()
    comment: str = ""

    @staticmethod
    def parse(r: Reader) -> "ServiceAllow":
        zone = r.wrap("zone", r.str_("zone", required=True), check_name)
        protocol = r.str_("protocol", required=True, choices={"tcp", "udp"})
        ports = tuple(r.int_list("ports", check_port, max_items=32))
        source_cidrs = tuple(r.str_list("source_cidrs", check_network, max_items=32))
        comment = r.str_("comment", "", max_length=128)
        r.done()
        if not ports:
            raise PolicyError("ports가 비어 있다", r.path)
        return ServiceAllow(zone, protocol, ports, source_cidrs, comment)


@dataclass(frozen=True)
class ForwardRule:
    name: str
    from_zone: str
    to_zone: str
    action: str  # accept | drop | reject
    protocol: str | None = None
    ports: tuple[int, ...] = ()
    source_cidrs: tuple[str, ...] = ()
    destination_cidrs: tuple[str, ...] = ()
    log: bool = False

    @staticmethod
    def parse(r: Reader) -> "ForwardRule":
        name = r.wrap("name", r.str_("name", required=True), check_name)
        from_zone = r.wrap("from_zone", r.str_("from_zone", required=True), check_name)
        to_zone = r.wrap("to_zone", r.str_("to_zone", required=True), check_name)
        action = r.str_("action", required=True, choices={"accept", "drop", "reject"})
        protocol = r.str_("protocol", None, choices={"tcp", "udp", "icmp", "any"})
        ports = tuple(r.int_list("ports", check_port, max_items=32))
        source_cidrs = tuple(r.str_list("source_cidrs", check_network, max_items=32))
        destination_cidrs = tuple(r.str_list("destination_cidrs", check_network, max_items=32))
        log = r.bool_("log", False)
        r.done()
        if ports and protocol not in {"tcp", "udp"}:
            raise PolicyError("ports는 tcp/udp 에서만 쓴다", r.path)
        return ForwardRule(name, from_zone, to_zone, action, protocol, ports, source_cidrs,
                           destination_cidrs, log)


@dataclass(frozen=True)
class FirewallPolicy:
    zones: tuple[str, ...]
    masquerade_wans: tuple[str, ...]
    default_forward: str = "drop"
    zone_forward: tuple[tuple[str, str], ...] = ()
    forward_rules: tuple[ForwardRule, ...] = ()
    service_allows: tuple[ServiceAllow, ...] = ()
    port_forwards: tuple[PortForward, ...] = ()
    mgmt_allow_cidrs: tuple[str, ...] = ()
    mgmt_ssh_port: int = 22
    quarantine_allow_dhcp_dns: bool = True
    captive_portal_ipv4: str | None = None
    log_dropped: bool = True
    mss_clamp: bool = True
    invalid_ct_drop: bool = True

    @staticmethod
    def parse(r: Reader) -> "FirewallPolicy":
        zones = tuple(r.str_list("zones", check_name, max_items=64))
        masquerade = tuple(r.str_list("masquerade_wans", check_name, max_items=16))
        default_forward = r.str_("default_forward", "drop", choices={"drop", "reject"})
        pairs_raw = r.list_("zone_forward", max_items=256)
        zone_forward: list[tuple[str, str]] = []
        for index, item in enumerate(pairs_raw):
            if not isinstance(item, dict) or set(item) - {"from", "to"} or "from" not in item or "to" not in item:
                raise PolicyError('{"from": ..., "to": ...} 형식이어야 한다', f"{r.path}.zone_forward[{index}]")
            zone_forward.append((check_name(item["from"]), check_name(item["to"])))
        forward_rules = tuple(ForwardRule.parse(x) for x in r.objs("forward_rules", max_items=512))
        service_allows = tuple(ServiceAllow.parse(x) for x in r.objs("service_allows", max_items=128))
        port_forwards = tuple(PortForward.parse(x) for x in r.objs("port_forwards", max_items=256))
        mgmt_allow = tuple(r.str_list("mgmt_allow_cidrs", check_network, max_items=32))
        mgmt_ssh_port = r.wrap("mgmt_ssh_port", r.int_("mgmt_ssh_port", 22), check_port)
        quarantine_allow = r.bool_("quarantine_allow_dhcp_dns", True)
        captive = r.str_("captive_portal_ipv4", None)
        log_dropped = r.bool_("log_dropped", True)
        mss_clamp = r.bool_("mss_clamp", True)
        invalid_drop = r.bool_("invalid_ct_drop", True)
        r.done()

        if captive:
            captive = r.wrap("captive_portal_ipv4", captive, lambda v: check_address(v, 4))
        if not zones:
            raise PolicyError("zones가 비어 있다", r.path)
        if len(set(zones)) != len(zones):
            raise PolicyError("중복 zone 이름", r.path)
        zone_set = set(zones)
        for src, dst in zone_forward:
            if src not in zone_set or dst not in zone_set:
                raise PolicyError(f"zone_forward가 미정의 zone을 참조한다: {src}->{dst}", r.path)
        for rule in forward_rules:
            if rule.from_zone not in zone_set or rule.to_zone not in zone_set:
                raise PolicyError(f"forward_rule '{rule.name}'이 미정의 zone을 참조한다", r.path)
        for allow in service_allows:
            if allow.zone not in zone_set:
                raise PolicyError(f"service_allow가 미정의 zone을 참조한다: {allow.zone}", r.path)
        names = [rule.name for rule in forward_rules]
        if len(set(names)) != len(names):
            raise PolicyError("중복 forward_rule 이름", r.path)
        pf_names = [pf.name for pf in port_forwards]
        if len(set(pf_names)) != len(pf_names):
            raise PolicyError("중복 port_forward 이름", r.path)
        return FirewallPolicy(zones, masquerade, default_forward, tuple(zone_forward), forward_rules,
                              service_allows, port_forwards, mgmt_allow, mgmt_ssh_port,
                              quarantine_allow, captive, log_dropped, mss_clamp, invalid_drop)


@dataclass(frozen=True)
class DnsPolicy:
    enabled: bool = True
    listen_segments: tuple[str, ...] = ()
    forwarders: tuple[str, ...] = ()
    forward_tls: bool = True
    forward_tls_hostnames: tuple[str, ...] = ()
    blocked_domains: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    rpz_zones: tuple[str, ...] = ()
    log_queries: bool = False
    dnstap_socket: str | None = None
    cache_max_mb: int = 32
    minimal_responses: bool = True

    @staticmethod
    def parse(r: Reader) -> "DnsPolicy":
        enabled = r.bool_("enabled", True)
        listen_segments = tuple(r.str_list("listen_segments", check_name, max_items=64))
        forwarders = tuple(r.str_list("forwarders", check_address, max_items=8))
        forward_tls = r.bool_("forward_tls", True)
        hostnames = tuple(r.str_list("forward_tls_hostnames", check_domain, max_items=8))
        blocked = tuple(r.str_list("blocked_domains", check_domain, max_items=200000))
        allowed = tuple(r.str_list("allowed_domains", check_domain, max_items=10000))
        rpz = tuple(r.str_list("rpz_zones", None, max_items=16))
        log_queries = r.bool_("log_queries", False)
        dnstap = r.str_("dnstap_socket", None, max_length=256)
        cache = r.int_("cache_max_mb", 32, minimum=4, maximum=1024)
        minimal = r.bool_("minimal_responses", True)
        r.done()
        if enabled and not forwarders:
            raise PolicyError("DNS를 켜면 forwarders가 필요하다", r.path)
        if forward_tls and hostnames and len(hostnames) != len(forwarders):
            raise PolicyError("forward_tls_hostnames 개수가 forwarders와 다르다", r.path)
        overlap = set(blocked) & set(allowed)
        if overlap:
            raise PolicyError(f"blocked와 allowed에 동시 포함된 도메인: {sorted(overlap)[:5]}", r.path)
        return DnsPolicy(enabled, listen_segments, forwarders, forward_tls, hostnames, blocked,
                         allowed, rpz, log_queries, dnstap, cache, minimal)


@dataclass(frozen=True)
class QosProfile:
    wan: str
    enabled: bool = True
    download_mbit: float = 0.0
    upload_mbit: float = 0.0
    mode: str = "diffserv4"  # besteffort | diffserv4 | diffserv8
    rtt_ms: int = 50
    nat: bool = True
    ack_filter: bool = True
    ingress_shaping: bool = True
    ifb_device: str | None = None

    @staticmethod
    def parse(r: Reader) -> "QosProfile":
        wan = r.wrap("wan", r.str_("wan", required=True), check_name)
        enabled = r.bool_("enabled", True)
        download = r.float_("download_mbit", 0.0, minimum=0.0, maximum=100000.0)
        upload = r.float_("upload_mbit", 0.0, minimum=0.0, maximum=100000.0)
        mode = r.str_("mode", "diffserv4", choices={"besteffort", "diffserv4", "diffserv8"})
        rtt = r.int_("rtt_ms", 50, minimum=1, maximum=1000)
        nat = r.bool_("nat", True)
        ack_filter = r.bool_("ack_filter", True)
        ingress = r.bool_("ingress_shaping", True)
        ifb = r.str_("ifb_device", None)
        r.done()
        if ifb:
            ifb = r.wrap("ifb_device", ifb, check_ifname)
        if enabled and upload <= 0:
            raise PolicyError("QoS를 켜면 upload_mbit가 필요하다", r.path)
        if enabled and ingress and download <= 0:
            raise PolicyError("ingress shaping을 켜면 download_mbit가 필요하다", r.path)
        return QosProfile(wan, enabled, download, upload, mode, rtt, nat, ack_filter, ingress,
                          ifb or f"ifb-{wan}")


@dataclass(frozen=True)
class MgmtTunnel:
    enabled: bool = False
    interface: str = "mooker-mgmt"
    address: str = ""
    listen_port: int | None = None
    private_key_ref: str = "mgmt-wg-private"
    peer_public_key: str = ""
    peer_endpoint: str = ""
    allowed_ips: tuple[str, ...] = ()
    keepalive_s: int = 25
    mtu: int = 1380
    table: int | None = None

    @staticmethod
    def parse(r: Reader) -> "MgmtTunnel":
        enabled = r.bool_("enabled", False)
        interface = r.wrap("interface", r.str_("interface", "mooker-mgmt"), check_ifname)
        address = r.str_("address", "")
        listen_port = r.int_("listen_port", None, minimum=1, maximum=65535)
        private_key_ref = r.wrap("private_key_ref", r.str_("private_key_ref", "mgmt-wg-private"), check_secret_ref)
        peer_public_key = r.str_("peer_public_key", "", max_length=64)
        peer_endpoint = r.str_("peer_endpoint", "", max_length=256)
        allowed_ips = tuple(r.str_list("allowed_ips", check_network, max_items=32))
        keepalive = r.int_("keepalive_s", 25, minimum=0, maximum=600)
        mtu = r.int_("mtu", 1380, minimum=576, maximum=1420)
        table = r.int_("table", None, minimum=1, maximum=252)
        r.done()
        if not enabled:
            return MgmtTunnel(False, interface, address, listen_port, private_key_ref, peer_public_key,
                              peer_endpoint, allowed_ips, keepalive, mtu, table)
        if not address:
            raise PolicyError("관리 터널은 address(CIDR)가 필요하다", r.path)
        address = r.wrap("address", address, check_cidr)
        if not peer_public_key or len(peer_public_key) != 44 or not peer_public_key.endswith("="):
            raise PolicyError("peer_public_key는 base64 44자 WireGuard 공개키여야 한다", r.path)
        if ":" not in peer_endpoint:
            raise PolicyError("peer_endpoint는 host:port 형식이어야 한다", r.path)
        if not allowed_ips:
            raise PolicyError("allowed_ips가 비어 있다(최소 권한 원칙에 따라 명시한다)", r.path)
        for cidr in allowed_ips:
            network = ipaddress.ip_network(cidr)
            if network.prefixlen == 0:
                raise BaselineViolation("관리 터널 allowed_ips에 0.0.0.0/0 은 허용하지 않는다", r.path)
        return MgmtTunnel(True, interface, address, listen_port, private_key_ref, peer_public_key,
                          peer_endpoint, allowed_ips, keepalive, mtu, table)


@dataclass(frozen=True)
class CommitConfirm:
    """적용을 누가 확정하는가.

    - ``central``: 중앙 플랫폼이 확정한다. Agent가 적용 후 heartbeat로 중앙 도달을
      확인하고 confirm한다. 운영 기본값.
    - ``manual``:  사람이 ``mooker-router confirm``으로 확정한다. 중앙 플랫폼이
      없는 랩/개발 장비, 그리고 SSH로 원격 작업할 때 쓴다. 접속이 끊기면 confirm을
      할 수 없으므로 타이머가 장비를 되돌린다 — 이것이 정확히 원하는 동작이다.
    - ``none``:    검증만 통과하면 즉시 확정한다. 콘솔이 확보된 장비에서만 쓴다.
      적용 후 접속이 끊기는 사고를 막아주지 못한다.
    """

    mode: str = "central"
    timeout_s: int = 300
    min_timeout_s: int = 60

    @property
    def requires_confirm(self) -> bool:
        return self.mode in {"central", "manual"}

    @property
    def require_central_confirm(self) -> bool:
        return self.mode == "central"

    @staticmethod
    def parse(r: Reader | None) -> "CommitConfirm":
        if r is None:
            return CommitConfirm()
        timeout = r.int_("timeout_s", 300, minimum=60, maximum=3600)
        mode = r.str_("mode", None, choices={"central", "manual", "none"})
        # 구 스키마 호환: require_central_confirm(bool)을 mode로 옮긴다.
        legacy = r.bool_("require_central_confirm", True)
        r.done()
        if mode is None:
            mode = "central" if legacy else "none"
        return CommitConfirm(mode, timeout)


@dataclass(frozen=True)
class VerifySpec:
    require_wan_online: bool = True
    require_dns: bool = True
    require_control_plane: bool = True
    require_mgmt_tunnel: bool = False
    control_plane_url: str = ""
    dns_probe_name: str = "www.example.com"
    per_check_timeout_s: float = 5.0
    settle_delay_s: float = 3.0

    @staticmethod
    def parse(r: Reader | None) -> "VerifySpec":
        if r is None:
            return VerifySpec()
        spec = VerifySpec(
            require_wan_online=r.bool_("require_wan_online", True),
            require_dns=r.bool_("require_dns", True),
            require_control_plane=r.bool_("require_control_plane", True),
            require_mgmt_tunnel=r.bool_("require_mgmt_tunnel", False),
            control_plane_url=r.str_("control_plane_url", "", max_length=512),
            dns_probe_name=r.wrap("dns_probe_name", r.str_("dns_probe_name", "www.example.com"), check_domain),
            per_check_timeout_s=r.float_("per_check_timeout_s", 5.0, minimum=1.0, maximum=60.0),
            settle_delay_s=r.float_("settle_delay_s", 3.0, minimum=0.0, maximum=60.0),
        )
        r.done()
        if spec.require_control_plane and not spec.control_plane_url.startswith(("http://", "https://")):
            raise PolicyError("control_plane_url이 필요하다", r.path)
        return spec


# ---------------------------------------------------------------------------
# 최상위 정책
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RouterPolicy:
    schema_version: int
    revision: int
    gateway_id: str
    tenant: str
    site: str
    generated_at: str
    ip_forward: bool
    ipv6_forward: bool
    wan_links: tuple[WanLink, ...]
    bridges: tuple[BridgeSpec, ...]
    lans: tuple[LanSegment, ...]
    vrfs: tuple[VrfSpec, ...]
    firewall: FirewallPolicy
    dns: DnsPolicy
    qos: tuple[QosProfile, ...]
    mgmt_tunnel: MgmtTunnel
    commit_confirm: CommitConfirm
    verify: VerifySpec
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    # --- 조회 헬퍼 ---------------------------------------------------------
    def wan(self, name: str) -> WanLink:
        for link in self.wan_links:
            if link.name == name:
                return link
        raise KeyError(name)

    def lan(self, name: str) -> LanSegment:
        for segment in self.lans:
            if segment.name == name:
                return segment
        raise KeyError(name)

    def segments_in_zone(self, zone: str) -> tuple[LanSegment, ...]:
        return tuple(s for s in self.lans if s.zone == zone)

    @property
    def wan_zone(self) -> str:
        return "wan"

    @property
    def dns_listen_segments(self) -> tuple[LanSegment, ...]:
        if not self.dns.enabled:
            return ()
        if self.dns.listen_segments:
            return tuple(s for s in self.lans if s.name in self.dns.listen_segments)
        return self.lans

    @property
    def dhcp_segments(self) -> tuple[LanSegment, ...]:
        return tuple(s for s in self.lans if s.dhcp is not None)

    # --- 파싱 --------------------------------------------------------------
    @staticmethod
    def parse(data: Any) -> "RouterPolicy":
        r = Reader(data, "policy")
        schema_version = r.int_("schema_version", required=True, minimum=1, maximum=SCHEMA_VERSION)
        revision = r.int_("revision", required=True, minimum=1)
        gateway_id = r.str_("gateway_id", required=True, max_length=64)
        tenant = r.str_("tenant", required=True, max_length=128)
        site = r.str_("site", required=True, max_length=128)
        generated_at = r.str_("generated_at", required=True, max_length=64)
        ip_forward = r.bool_("ip_forward", True)
        ipv6_forward = r.bool_("ipv6_forward", False)
        wan_links = tuple(WanLink.parse(x) for x in r.objs("wan_links", max_items=8))
        bridges = tuple(BridgeSpec.parse(x) for x in r.objs("bridges", max_items=16))
        lans = tuple(LanSegment.parse(x) for x in r.objs("lans", max_items=128))
        vrfs = tuple(VrfSpec.parse(x) for x in r.objs("vrfs", max_items=16))
        firewall_reader = r.obj("firewall", required=True)
        dns_reader = r.obj("dns")
        qos = tuple(QosProfile.parse(x) for x in r.objs("qos", max_items=8))
        mgmt_reader = r.obj("mgmt_tunnel")
        commit_reader = r.obj("commit_confirm")
        verify_reader = r.obj("verify")
        r.done()

        firewall = FirewallPolicy.parse(firewall_reader)
        dns = DnsPolicy.parse(dns_reader) if dns_reader else DnsPolicy(enabled=False)
        mgmt_tunnel = MgmtTunnel.parse(mgmt_reader) if mgmt_reader else MgmtTunnel()
        policy = RouterPolicy(
            schema_version=schema_version,
            revision=revision,
            gateway_id=gateway_id,
            tenant=tenant,
            site=site,
            generated_at=generated_at,
            ip_forward=ip_forward,
            ipv6_forward=ipv6_forward,
            wan_links=wan_links,
            bridges=bridges,
            lans=lans,
            vrfs=vrfs,
            firewall=firewall,
            dns=dns,
            qos=qos,
            mgmt_tunnel=mgmt_tunnel,
            commit_confirm=CommitConfirm.parse(commit_reader),
            verify=VerifySpec.parse(verify_reader),
            raw=dict(data),
        )
        validate_cross_references(policy)
        enforce_baseline(policy)
        return policy


def validate_cross_references(policy: RouterPolicy) -> None:
    """객체 간 참조 정합성과 주소 충돌을 검증한다."""
    if not policy.wan_links:
        raise PolicyError("WAN 링크가 최소 1개 필요하다", "policy.wan_links")
    if not policy.lans:
        raise PolicyError("LAN segment가 최소 1개 필요하다", "policy.lans")

    for names, label in (
        ([w.name for w in policy.wan_links], "wan_links"),
        ([b.name for b in policy.bridges], "bridges"),
        ([s.name for s in policy.lans], "lans"),
        ([v.name for v in policy.vrfs], "vrfs"),
    ):
        if len(set(names)) != len(names):
            raise PolicyError("중복 이름", f"policy.{label}")

    bridge_names = {b.name for b in policy.bridges}
    vrf_names = {v.name for v in policy.vrfs}
    wan_names = {w.name for w in policy.wan_links}
    wan_ifaces = {w.interface for w in policy.wan_links}

    # 브리지 포트가 WAN 인터페이스를 삼키면 회선이 죽는다.
    for bridge in policy.bridges:
        conflict = set(bridge.ports) & wan_ifaces
        if conflict:
            raise PolicyError(f"bridge '{bridge.name}' port가 WAN 인터페이스와 겹친다: {sorted(conflict)}",
                              "policy.bridges")

    # 장치 이름 유일성: 같은 리눅스 디바이스를 두 segment가 만들 수 없다.
    devices: dict[str, str] = {}
    for segment in policy.lans:
        if segment.interface in devices:
            raise PolicyError(
                f"인터페이스 '{segment.interface}'를 segment '{devices[segment.interface]}'와 "
                f"'{segment.name}'이 동시에 소유한다", "policy.lans")
        devices[segment.interface] = segment.name
        if segment.vlan_link and segment.vlan_link not in bridge_names and segment.vlan_link not in {
            w.interface for w in policy.wan_links
        } and segment.vlan_link not in {s.interface for s in policy.lans}:
            # 물리 NIC를 직접 지정하는 경우도 허용하지만, 최소한 정책 내에서
            # 알려진 디바이스이거나 bridge여야 오타를 잡을 수 있다.
            if segment.vlan_link not in {b.name for b in policy.bridges}:
                raise PolicyError(
                    f"vlan_link '{segment.vlan_link}'가 정책 내 bridge/인터페이스로 정의되지 않았다",
                    "policy.lans")
        if segment.vrf and segment.vrf not in vrf_names:
            raise PolicyError(f"미정의 VRF 참조: {segment.vrf}", "policy.lans")
        if segment.zone not in policy.firewall.zones:
            raise PolicyError(f"segment '{segment.name}'의 zone '{segment.zone}'이 firewall.zones에 없다",
                              "policy.lans")

    # untagged_ports는 해당 bridge의 port여야 하고, 한 포트는 하나의 VLAN에만 untagged다.
    bridge_by_name = {b.name: b for b in policy.bridges}
    untagged_owner: dict[str, str] = {}
    for segment in policy.lans:
        if not segment.untagged_ports:
            continue
        bridge = bridge_by_name.get(segment.vlan_link or "")
        if bridge is None:
            raise PolicyError(
                f"segment '{segment.name}'의 untagged_ports는 vlan_link가 bridge일 때만 쓴다", "policy.lans")
        if not bridge.vlan_filtering:
            raise PolicyError(
                f"bridge '{bridge.name}'에 vlan_filtering이 꺼져 있어 untagged_ports를 적용할 수 없다",
                "policy.lans")
        for port in segment.untagged_ports:
            if port not in bridge.ports:
                raise PolicyError(f"'{port}'는 bridge '{bridge.name}'의 port가 아니다", "policy.lans")
            if port in untagged_owner:
                raise PolicyError(
                    f"포트 '{port}'가 segment '{untagged_owner[port]}'와 '{segment.name}'에서 "
                    f"동시에 untagged다", "policy.lans")
            untagged_owner[port] = segment.name

    # VLAN ID 중복(같은 상위 링크 기준)
    seen_vlan: set[tuple[str, int]] = set()
    for segment in policy.lans:
        if segment.vlan_id is None:
            continue
        key = (segment.vlan_link or "", segment.vlan_id)
        if key in seen_vlan:
            raise PolicyError(f"같은 상위 링크에 VLAN {segment.vlan_id}가 중복 정의되었다", "policy.lans")
        seen_vlan.add(key)

    # LAN 서브넷 겹침
    networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for segment in policy.lans:
        for cidr in segment.addresses:
            network = ipaddress.ip_interface(cidr).network
            for other_name, other in networks:
                if network.version == other.version and network.overlaps(other):
                    raise PolicyError(
                        f"segment '{segment.name}'({network})과 '{other_name}'({other}) 서브넷이 겹친다",
                        "policy.lans")
            networks.append((segment.name, network))

    # 방화벽/QoS/DNS 참조
    for name in policy.firewall.masquerade_wans:
        if name not in wan_names:
            raise PolicyError(f"masquerade_wans가 미정의 WAN을 참조한다: {name}", "policy.firewall")
    for forward in policy.firewall.port_forwards:
        if forward.wan not in wan_names:
            raise PolicyError(f"port_forward '{forward.name}'가 미정의 WAN을 참조한다", "policy.firewall")
        if not any(address_in_network(forward.to_address, str(ipaddress.ip_interface(cidr).network))
                   for segment in policy.lans for cidr in segment.addresses):
            raise PolicyError(
                f"port_forward '{forward.name}'의 to_address({forward.to_address})가 어떤 LAN 서브넷에도 없다",
                "policy.firewall")
    for profile in policy.qos:
        if profile.wan not in wan_names:
            raise PolicyError(f"qos가 미정의 WAN을 참조한다: {profile.wan}", "policy.qos")
    if len({p.wan for p in policy.qos}) != len(policy.qos):
        raise PolicyError("한 WAN에 QoS 프로필이 중복 정의되었다", "policy.qos")
    lan_names = {s.name for s in policy.lans}
    for name in policy.dns.listen_segments:
        if name not in lan_names:
            raise PolicyError(f"dns.listen_segments가 미정의 segment를 참조한다: {name}", "policy.dns")

    # 다회선인데 metric이 같으면 failover 판단이 불가능하다.
    metrics = [w.metric for w in policy.wan_links]
    if len(policy.wan_links) > 1 and len(set(metrics)) != len(metrics):
        raise PolicyError("다회선 구성은 WAN마다 서로 다른 metric이 필요하다", "policy.wan_links")


def enforce_baseline(policy: RouterPolicy) -> None:
    """하위 정책이 완화할 수 없는 보안 baseline.

    중앙에서 잘못된(또는 악의적인) 정책이 내려와도 다음은 지켜진다.
      1. 관리 접근 대역(mgmt_allow_cidrs)이 비어 있으면 거부한다.
         → 적용 후 아무도 접속할 수 없는 상태를 만들지 않는다.
      2. 관리 접근 대역에 0.0.0.0/0 또는 ::/0 을 쓸 수 없다.
      3. WAN zone에서 Gateway 자신으로 들어오는 서비스 개방은 금지한다.
         (인바운드 관리 포트를 열지 않는다는 아키텍처 원칙)
      4. 검증 단계에서 제어 채널 확인을 끄면서 동시에 중앙 confirm을 요구할 수 없다.
      5. commit-confirm 타임아웃은 최소 60초 이상이어야 한다.
    """
    firewall = policy.firewall
    if not firewall.mgmt_allow_cidrs:
        raise BaselineViolation(
            "mgmt_allow_cidrs가 비어 있다. 적용 후 관리 접근 경로가 사라진다", "policy.firewall.mgmt_allow_cidrs")
    for cidr in firewall.mgmt_allow_cidrs:
        if ipaddress.ip_network(cidr).prefixlen == 0:
            raise BaselineViolation("mgmt_allow_cidrs에 전체 대역(0.0.0.0/0, ::/0)은 허용하지 않는다",
                                    "policy.firewall.mgmt_allow_cidrs")
    for allow in firewall.service_allows:
        if allow.zone == policy.wan_zone:
            raise BaselineViolation(
                "WAN zone에서 Gateway로의 서비스 개방은 금지된다. 필요한 노출은 port_forward로 정의한다",
                "policy.firewall.service_allows")
    if policy.commit_confirm.mode == "central" and not policy.verify.require_control_plane:
        raise BaselineViolation(
            "commit_confirm.mode=central은 제어 채널 검증을 끌 수 없다. "
            "중앙 플랫폼이 없다면 mode를 manual로 둔다",
            "policy.verify.require_control_plane")
    if policy.commit_confirm.timeout_s < policy.commit_confirm.min_timeout_s:
        raise BaselineViolation("commit-confirm 타임아웃이 너무 짧다", "policy.commit_confirm.timeout_s")
    if policy.mgmt_tunnel.enabled and policy.verify.require_mgmt_tunnel is False:
        # 경고 수준이지만 baseline은 아니다. 정보만 남긴다.
        pass
