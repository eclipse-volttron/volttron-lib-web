# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}
"""Authorization policy for the VUI RPC proxy.

The ``/vui/platforms/:platform/agents/:vip_identity/rpc/:method`` endpoint forwards calls using the web service's
own VIP identity. A web user holding the ``vui`` group must therefore only be able to reach the RPC surface that the
operator has explicitly opened. Two layers decide whether a call may be forwarded:

1. A fixed deny-list. The platform's own services (``platform.auth``, ``platform.web``, ``config.store``,
   ``platform.driver``) are never reachable through the proxy, and neither are the agent lifecycle and installation
   methods of ``platform.control``. The dedicated ``/agents`` and ``/devices`` VUI endpoints provide the supported
   management and device operations. This layer cannot be changed by configuration.

2. A configured allow-list. Nothing is forwarded unless an allow-list entry matches the target platform, VIP identity
   and method. The allow-list is the ``rpc-allow-list`` option of the ``[web]`` section of the platform config file.
   Each entry occupies one line (INI continuation lines are indented) and has the form::

       [platform-glob:] identity-glob: method-glob[, method-glob ...]

   For example::

       rpc-allow-list =
           platform.historian: query*
           my.app.*: *
           building2: some.agent: get_status, get_config

   Patterns are shell-style globs (``*``, ``?``, ``[seq]``) matched case-sensitively against the whole name. A line
   with two fields applies to every platform. ``*: *`` opens every method of every installed agent that is not
   covered by the deny-list. When the option is absent the proxy refuses every request.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from volttron.client.known_identities import AUTH, CONFIGURATION_STORE, CONTROL, PLATFORM_DRIVER, PLATFORM_WEB

# Peers that are refused entirely, whatever the allow-list says.
RPC_PROXY_DENIED_PEERS = frozenset({AUTH, PLATFORM_WEB, CONFIGURATION_STORE, PLATFORM_DRIVER})
# Methods refused on otherwise reachable peers, whatever the allow-list says.
RPC_PROXY_DENIED_METHODS: Mapping[str, frozenset[str]] = {
    CONTROL: frozenset({'install_agent', 'install_agent_from_message_bus', 'install_library', 'remove_library',
                        'receive_wheel', 'remove_agent', 'shutdown', 'stop_platform', 'clear_status',
                        'prioritize_agent', 'tag_agent'}),
}

ANY = '*'


class RpcAllowListError(ValueError):
    """Raised when the rpc-allow-list configuration cannot be parsed."""


def _compile(glob: str) -> re.Pattern:
    # fnmatch.translate anchors the expression; compiling it directly keeps matching case-sensitive on every OS.
    return re.compile(fnmatch.translate(glob))


@dataclass(frozen=True)
class AllowListEntry:
    platform: str
    identity: str
    methods: tuple[str, ...]

    def __post_init__(self):
        object.__setattr__(self, '_platform_re', _compile(self.platform))
        object.__setattr__(self, '_identity_re', _compile(self.identity))
        object.__setattr__(self, '_method_res', tuple(_compile(m) for m in self.methods))

    def matches_target(self, platform: str, identity: str) -> bool:
        return bool(self._platform_re.match(platform) and self._identity_re.match(identity))

    def matches_method(self, method: str) -> bool:
        return any(m.match(method) for m in self._method_res)

    def __str__(self):
        return f'{self.platform}: {self.identity}: {", ".join(self.methods)}'


def _split_methods(methods: str | Iterable[str], line: str) -> tuple[str, ...]:
    if isinstance(methods, str):
        methods = methods.split(',')
    cleaned = tuple(m.strip() for m in methods if m and m.strip())
    if not cleaned:
        raise RpcAllowListError(f'rpc-allow-list entry {line!r} does not name any methods.')
    return cleaned


def parse_entry(target: str, methods: str | Iterable[str] | None = None) -> AllowListEntry:
    """Parse one allow-list entry.

    ``target`` is either a whole line (``[platform:] identity: methods``) when ``methods`` is None, or just the
    ``[platform:] identity`` part when ``methods`` is supplied separately (dictionary form).
    """
    line = target if methods is None else f'{target}: {methods}'
    fields = [f.strip() for f in target.split(':')]
    if methods is None:
        if len(fields) < 2:
            raise RpcAllowListError(f'rpc-allow-list entry {line!r} must have the form '
                                    f'"[platform:] identity: method, method...".')
        methods = fields.pop()
    if len(fields) == 1:
        platform, identity = ANY, fields[0]
    elif len(fields) == 2:
        platform, identity = fields
    else:
        raise RpcAllowListError(f'rpc-allow-list entry {line!r} has too many fields; expected '
                                f'"[platform:] identity: method, method...".')
    if not platform or not identity:
        raise RpcAllowListError(f'rpc-allow-list entry {line!r} has an empty platform or identity.')
    return AllowListEntry(platform, identity, _split_methods(methods, line))


def parse_allow_list(allow_list) -> tuple[AllowListEntry, ...]:
    """Parse the configured allow-list.

    Accepts the raw multi-line string from the platform config file, a list of such lines, or a mapping of
    ``"[platform:] identity"`` to a method glob or list of method globs. None and empty values yield no entries.
    """
    if allow_list is None:
        return ()
    if isinstance(allow_list, str):
        allow_list = allow_list.splitlines()
    if isinstance(allow_list, Mapping):
        return tuple(parse_entry(target, methods) for target, methods in allow_list.items())
    try:
        lines = [line for line in allow_list if line and str(line).strip()]
    except TypeError:
        raise RpcAllowListError(f'rpc-allow-list must be a string, list or mapping, not {type(allow_list).__name__}.')
    entries = []
    for line in lines:
        if not isinstance(line, str):
            raise RpcAllowListError(f'rpc-allow-list entries must be strings, got {line!r}.')
        entries.append(parse_entry(line))
    return tuple(entries)


class RpcProxyPolicy:
    """Decides which RPC calls the VUI proxy may forward. See the module docstring for the rules."""

    def __init__(self, allow_list=None):
        self.entries: tuple[AllowListEntry, ...] = parse_allow_list(allow_list)

    @staticmethod
    def is_denied(vip_identity: str, method_name: str | None = None) -> bool:
        """True if the fixed deny-list refuses this peer, or this method on this peer."""
        if vip_identity in RPC_PROXY_DENIED_PEERS:
            return True
        return method_name is not None and method_name in RPC_PROXY_DENIED_METHODS.get(vip_identity, ())

    def permits_any(self, platform: str, vip_identity: str) -> bool:
        """True if some method on vip_identity could be forwarded, i.e. the peer is worth inspecting at all."""
        if self.is_denied(vip_identity):
            return False
        return any(e.matches_target(platform, vip_identity) for e in self.entries)

    def is_allowed(self, platform: str, vip_identity: str, method_name: str) -> bool:
        """True if the proxy may forward method_name to vip_identity on platform."""
        if self.is_denied(vip_identity, method_name):
            return False
        return any(e.matches_target(platform, vip_identity) and e.matches_method(method_name) for e in self.entries)

    def filter_methods(self, platform: str, vip_identity: str, methods: Iterable[str]) -> list[str]:
        """Return only those of methods that the proxy may forward to vip_identity on platform."""
        return [m for m in methods if self.is_allowed(platform, vip_identity, m)]

    def __eq__(self, other):
        return isinstance(other, RpcProxyPolicy) and self.entries == other.entries

    def __repr__(self):
        return f'RpcProxyPolicy([{", ".join(repr(str(e)) for e in self.entries)}])'
