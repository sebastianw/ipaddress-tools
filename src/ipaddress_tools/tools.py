from __future__ import annotations

import ipaddress
from threading import RLock
from typing import TYPE_CHECKING, Generic, TypeVar

_N = TypeVar("_N", ipaddress.IPv4Network, ipaddress.IPv6Network)

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence
    from typing import TypeAlias

    IPNetwork: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network
    UnspecifiedNetwork: TypeAlias = str | _N
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


class _BaseIPSet(Generic[_N]):
    version: int | None = None
    max_prefixlen: int = 0

    def __init__(self, supernet: UnspecifiedNetwork, used_networks: UnspecifiedNetworkSeq | None = None):
        _supernet = ipaddress.ip_network(supernet) if isinstance(supernet, str) else supernet
        if _supernet.version != self.version:
            msg = f"IP Version missmatch. Cannot create {self.__class__.__name__} from {supernet.__class__.__name__}"
            raise ValueError(msg)
        self.supernet = _supernet
        if used_networks is None:
            used_networks = []
        self._used_networks: set[_N] = self._init_used_networks(used_networks)
        self.lock = RLock()
        self._free_networks: set[_N] = set()
        self._update_free_networks()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.supernet}>"

    def _validate_network(self, input_network: UnspecifiedNetwork) -> _N:
        network = ipaddress.ip_network(input_network) if isinstance(input_network, str) else input_network
        if network.version != self.version:
            msg = f"IP Version missmatch. Cannot use {network} in {self}"
            raise ValueError(msg)
        return network

    def _init_used_networks(self, input_networks: UnspecifiedNetworkSeq) -> set[_N]:
        return {self._validate_network(n) for n in input_networks}

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

    def _update_free_networks(self) -> None:
        new_free_nets: list[IPNetwork] = []
        for used_network in self._used_networks:
            for free_net in self._free_networks:
                if used_network.subnet_of(free_net):
                    new_free_nets.extend(free_net.address_exclude(used_network))
                else:
                    new_free_nets.append(free_net)
            self._free_networks = new_free_nets

    def get_free_networks(self, prefixlen: int) -> Generator[_N, None, None]:
        for free_network in sorted(self._free_networks):
            if free_network.prefixlen == prefixlen:
                yield free_network
            elif free_network.prefixlen < prefixlen:
                # Splitting into subnets
                yield from free_network.subnets(new_prefix=prefixlen)


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
