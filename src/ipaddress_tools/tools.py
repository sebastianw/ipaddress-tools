from __future__ import annotations

import ipaddress
from threading import RLock
from typing import TYPE_CHECKING, Generic, TypeVar

_N = TypeVar("_N", ipaddress.IPv4Network, ipaddress.IPv6Network)

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence
    from typing import TypeAlias, TypeGuard

    IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
    UnspecifiedNetwork: TypeAlias = str | IPNetwork
    UnspecifiedNetworkSeq: TypeAlias = Sequence[UnspecifiedNetwork]


def ip_set(address: UnspecifiedNetwork, used_networks: UnspecifiedNetworkSeq | None = None) -> IPv4Set | IPv6Set:
    if used_networks is None:
        used_networks = []
    supernet = ipaddress.ip_network(address) if isinstance(address, str) else address
    if supernet.version == 4:
        assert isinstance(supernet, ipaddress.IPv4Network)
        return IPv4Set(supernet, used_networks)
    if supernet.version == 6:
        assert isinstance(supernet, ipaddress.IPv6Network)
        return IPv6Set(supernet, used_networks)
    msg = f"IP Version of Supernet is unknown: {supernet.version}"
    raise ValueError(msg)


def overlap(a: tuple[int, int], b: list[tuple[int, int]]):
    for x in b:
        if x[0] <= a[0] <= x[1] or x[0] <= a[1] <= x[1] or a[0] <= x[0] <= a[1] or a[0] <= x[1] <= a[1]:
            return x
    return False


def net_size_iterator(start: IPNetwork, cidr: int) -> Generator[tuple[int, int], None, None]:
    cidr_size = 2 ** (start.max_prefixlen - cidr)
    for s in range(int(start[0]), int(start[-1]), cidr_size):
        yield s, s + cidr_size - 1


class _BaseIPSet(Generic[_N]):
    version: int | None = None
    max_prefixlen: int = 0

    def __init__(self, supernet: UnspecifiedNetwork, used_networks: UnspecifiedNetworkSeq | None = None):
        self.lock = RLock()
        self.supernet: _N = self._normalize_network(supernet)
        if used_networks is None:
            used_networks = []
        self._used_networks: list[_N] = [self._normalize_network(n) for n in used_networks]
        self._used_network_map: dict[tuple[int, int], _N] = {}
        self._update_networks()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.supernet}>"

    def _normalize_network(self, _network: UnspecifiedNetwork) -> _N:
        network = ipaddress.ip_network(_network) if isinstance(_network, str) else _network
        if not self._version_compatible(network):
            msg = f"IP Version missmatch. Cannot use {network} in {self}"
            raise ValueError(msg)
        return network

    def _version_compatible(self, network: IPNetwork) -> TypeGuard[_N]:
        return self.version == network.version

    def _init_used_networks(self, input_networks: UnspecifiedNetworkSeq) -> set[_N]:
        return {self._normalize_network(n) for n in input_networks}

    @property
    def used_networks(self) -> Generator[IPNetwork, None, None]:
        yield from self._used_networks

    @used_networks.setter
    def used_networks(self, new_networks: UnspecifiedNetworkSeq) -> None:
        with self.lock:
            self._used_networks = self._init_used_networks(new_networks)

    def add_used_networks(self, input_networks: UnspecifiedNetworkSeq) -> None:
        with self.lock:
            self._used_networks.update(self._init_used_networks(input_networks))
            self._update_free_networks()

    def _update_networks(self) -> None:
        self._used_network_map = {(int(n[0]), int(n[-1])): n for n in self._used_networks}

    def get_free_networks(self, prefixlen: int) -> Generator[_N, None, None]:
        for n in net_size_iterator(self.supernet, prefixlen):
            o = overlap(n, self._used_network_map.keys())
            if o:
                # print(f"{ipaddress.ip_network((n[0], prefixlen))} overlaps with {self._used_network_map[o]}")
                continue
            yield ipaddress.ip_network((n[0], prefixlen))


class IPv4Set(_BaseIPSet[ipaddress.IPv4Network]):
    version = 4
    max_prefixlen = ipaddress.IPV4LENGTH

    def __init__(self, supernet: ipaddress.IPv4Network, used_networks: UnspecifiedNetworkSeq | None = None):
        super().__init__(supernet, used_networks)


class IPv6Set(_BaseIPSet[ipaddress.IPv6Network]):
    version = 6
    max_prefixlen = ipaddress.IPV6LENGTH

    def __init__(self, supernet: ipaddress.IPv6Network, used_networks: UnspecifiedNetworkSeq | None = None):
        super().__init__(supernet, used_networks)
