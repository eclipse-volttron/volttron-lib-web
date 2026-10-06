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

from __future__ import annotations

import base64
import gevent
import gevent.pywsgi
import logging
import mimetypes
import os
import re
import zlib

from collections import defaultdict
from gevent import Greenlet
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, field_validator, model_validator, SecretStr
from werkzeug import Response

from ws4py.server.geventserver import WSGIServer

from .admin_endpoints import AdminEndpoints
from .vui_endpoints import VUIEndpoints
from .rpc_proxy_policy import RpcProxyPolicy
from .authenticate_endpoint import AuthenticateEndpoints
from .csr_endpoints import CSREndpoints
from .webapp import WebApplicationWrapper


from volttron.utils.certs import Certs, CertWrapper
from volttron.utils.context import ClientContext
from volttron.utils.jsonrpc import  UNAUTHORIZED

from volttron.client.known_identities import PLATFORM_WEB
from volttron.client.vip.agent import Agent, Core, RPC
from volttron.server.decorators import service
from volttron.server.server_options import ServerOptions
from volttron.utils import jsonapi
from volttron.utils import set_agent_identity

# must be after importing of utils which imports grequest.
import requests

_log = logging.getLogger(__name__)


class CouldNotRegister(Exception):
    pass


class DuplicateEndpointError(Exception):
    pass


class ReservedRouteError(ValueError):
    """Raised when a peer tries to register a route that would shadow a platform-owned path."""
    pass


# Paths owned by the platform web service itself. Peer registrations that would match any of these are refused,
# because peer routes are consulted before the built-in routes and the forwarded request would otherwise let an
# arbitrary agent impersonate the login, administration or REST API endpoints.
RESERVED_ROUTE_PREFIXES = ('/authenticate', '/admin', '/vui')

# WSGI environment keys forwarded to peers for 'peer_route' and registered endpoints. Credentials
# (HTTP_AUTHORIZATION, HTTP_COOKIE) are deliberately excluded: the platform validates web users itself and a peer
# must never receive another user's bearer token or session cookie.
PEER_ENV_KEYS = ('HTTP_USER_AGENT', 'PATH_INFO', 'QUERY_STRING', 'REQUEST_METHOD', 'SERVER_PROTOCOL', 'REMOTE_ADDR',
                 'HTTP_ACCEPT_ENCODING', 'CONTENT_TYPE', 'SERVER_NAME', 'wsgi.url_scheme', 'HTTP_HOST')


def _path_is_reserved(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + '/') or path.startswith(prefix + '.')
               for prefix in RESERVED_ROUTE_PREFIXES)


def _regex_covers_reserved(compiled: re.Pattern) -> bool:
    """True if the route regex would match a reserved path or something beneath it.

    Two checks: probe paths under each reserved prefix, and inspect the literal text the pattern starts with
    (e.g. '^/vui/platforms/.*' never matches the probes but plainly targets a reserved subtree).
    """
    for prefix in RESERVED_ROUTE_PREFIXES:
        for probe in (prefix, prefix + '/', prefix + '/x', prefix + '/x/y'):
            if compiled.match(probe):
                return True
    literal = re.match(r'[^.^$*+?{}\\[\]|()]*', compiled.pattern.lstrip('^')).group()
    return _path_is_reserved(literal.rstrip('/')) or any(literal.startswith(p + '/') for p in RESERVED_ROUTE_PREFIXES)


def _insert_peer_route(routes: list, route: tuple) -> None:
    """Insert a peer route after the platform's own callable routes but before any static path routes.

    The built-in routes (/admin, /vui, /authenticate) must always be matched first, whatever a peer registers;
    the catch-all static route must always be matched last.
    """
    index = 0
    for i, (_, route_type, _) in enumerate(routes):
        if route_type == 'callable':
            index = i + 1
    routes.insert(index, route)


class HiddenPathError(Exception):
    """The requested file is inside the root but a path segment is hidden (begins with a dot)."""


def _safe_path_within_root(root_dir: str, path_info: str) -> str:
    """Return the resolved candidate path if it is strictly within root_dir and not hidden.

    Raises ValueError when the resolved candidate escapes the root so callers
    can return 403 without leaking file bytes. Uses Path.relative_to for
    containment. Raises HiddenPathError when any segment of the in-root path
    begins with a dot (``.git``, ``.env``, ``.htpasswd``); callers answer 404 so
    hidden files are indistinguishable from absent ones.

    :param root_dir: canonical (pre-resolved) root as stored in registered_routes
    :param path_info: raw PATH_INFO from the WSGI environment
    :returns: resolved absolute path string safe to pass to _sendfile
    :raises ValueError: if the resolved path escapes root_dir
    :raises HiddenPathError: if the in-root path contains a hidden segment
    """
    root = Path(root_dir).resolve()
    # Strip leading slashes before joining so Path('/abs') does not replace root.
    candidate = (root / path_info.lstrip('/')).resolve()
    # relative_to raises ValueError when candidate is outside root.
    relative = candidate.relative_to(root)
    if any(part.startswith('.') for part in relative.parts):
        raise HiddenPathError(str(relative))
    return str(candidate)


# Name of the directory inside an agent's data directory whose contents it may publish through the web service.
AGENT_WEB_ROOT_DIRNAME = 'web-root'


__PACKAGE_DIR__ = os.path.dirname(os.path.abspath(__file__))
__TEMPLATE_DIR__ = os.path.join(__PACKAGE_DIR__, "templates")
__STATIC_DIR__ = os.path.join(__PACKAGE_DIR__, "static")


# Our admin interface will use Jinja2 templates based upon the above paths
# reference api for using Jinja2 http://jinja.pocoo.org/docs/2.10/api/
# Using the FileSystemLoader instead of the package loader in this case however.
tplenv = Environment(
    loader=FileSystemLoader(__TEMPLATE_DIR__),
    autoescape=select_autoescape(['html', 'xml'])
)

class WebServiceConfig(BaseModel):
    model_config = ConfigDict(extra='allow', populate_by_name=True, validate_assignment=True,
                              arbitrary_types_allowed=True)
    bind_address: AnyHttpUrl = Field(validation_alias='bind_web_address')
    message_bus: str = Field(alias='messagebus')
    secret_key: SecretStr | None = Field(default=None, alias='web_secret_key')
    ssl_key: str | None = Field(default=None, alias='web_ssl_key')
    ssl_cert: str | None = Field(default=None, alias='web_ssl_cert')
    # Which RPC calls the VUI /rpc proxy may forward. Configured as the multi-line "rpc-allow-list" option of the
    # [web] section; see rpc_proxy_policy.py for the syntax. Empty by default, which closes the proxy.
    rpc_allow_list: RpcProxyPolicy = Field(default_factory=RpcProxyPolicy)
    # Needed to validate web_root_dir (declared first so its value is available to that validator); supplied by
    # the service from ServerOptions.
    volttron_home: Path = Field(default_factory=lambda: Path(ClientContext.get_volttron_home()))
    # Optional directory holding one web-root subdirectory per agent identity. When set, agents publish static
    # files from "<web_root_dir>/<identity>" instead of "<VOLTTRON_HOME>/agents/<identity>/data/web-root", so
    # their web files survive a reinstall of the agent. Configured as "web-root-dir" in the [web] section.
    web_root_dir: Path | None = Field(default=None)

    @field_validator('web_root_dir', mode='after')
    @classmethod
    def validate_web_root_dir(cls, web_root_dir: Path | None, info) -> Path | None:
        """Canonicalize web_root_dir and refuse locations that would expose the platform's own files.

        The directory must already exist so a typo fails loudly at startup instead of silently refusing every
        agent registration. It must not be the filesystem root, and it must not be VOLTTRON_HOME or any ancestor
        of it: per-agent subdirectories of such a root could be made to coincide with the keystore, credential
        store or configuration directories.
        """
        if web_root_dir is None:
            return None
        resolved = Path(web_root_dir).expanduser().resolve()
        if not resolved.is_dir():
            raise ValueError(f'Parameter "web_root_dir" must be an existing directory: {web_root_dir!s}')
        if resolved == Path(resolved.anchor):
            raise ValueError('Parameter "web_root_dir" must not be the filesystem root.')
        volttron_home = Path(info.data.get('volttron_home') or ClientContext.get_volttron_home()).expanduser().resolve()
        if resolved == volttron_home or resolved in volttron_home.parents:
            raise ValueError(f'Parameter "web_root_dir" must not be VOLTTRON_HOME or a directory containing it: '
                             f'{web_root_dir!s}')
        return resolved

    @field_validator('rpc_allow_list', mode='before')
    @classmethod
    def parse_rpc_allow_list(cls, value) -> RpcProxyPolicy:
        if isinstance(value, RpcProxyPolicy):
            return value
        # RpcAllowListError is a ValueError, so pydantic reports a bad entry as a normal validation error.
        return RpcProxyPolicy(value)

    @model_validator(mode='after')
    def validate_auth_requirements(self) -> WebServiceConfig:
        if self.bind_address.scheme == 'http' and self.secret_key is None:
            # TODO: Can we create a secret key for this session? Does that make sense?
            raise ValueError('Parameter "secret_key" is required when using the web service with an HTTP bind_address.')
        # TODO: We might want to handle cert loading here so we can validate if it is possible to get them?
        return self


@service
class PlatformWebService(Agent):
    """The service that is responsible for managing and serving registered pages

    Agents can register either a directory of files to serve or an rpc method
    that will be called during the request process.
    """
    class Meta:
        identity = PLATFORM_WEB

    def __init__(self, opts: ServerOptions, **kwargs):
        """
        Initialize the configuration of the base web service integration within the platform.

        """
        self.config = WebServiceConfig(message_bus=opts.messagebus, volttron_home=opts.volttron_home,
                                       **opts.services.get('web', {}))
        with set_agent_identity(self.Meta.identity):
            super().__init__(address=opts.service_address, **kwargs)

        self.endpoints = {}  # Maps from endpoint to peer.
        self.peer_routes = defaultdict(list)
        self.path_routes = defaultdict(list)
        self.registered_routes = []

        # Initialize the mimetypes so that we can guess at the passed mimetype
        if not mimetypes.inited:
            mimetypes.init()

        self._certs = Certs()

        self._csr_endpoints: CSREndpoints | None = None
        self.appContainer: WebApplicationWrapper | None = None
        self._server_greenlet: Greenlet | None = None
        self._admin_endpoints: AdminEndpoints | None = None
        self._vui_endpoints: VUIEndpoints | None = None

    @property
    def ssl_cert(self) -> str | None:
        """
        Web server ssl certificate path
        """
        return self.config.ssl_cert

    @property
    def ssl_key(self) -> str | None:
        """
        Web server ssl key path
        """
        return self.config.ssl_key

    @property
    def rpc_proxy_policy(self) -> RpcProxyPolicy:
        """
        Policy deciding which RPC calls the VUI /rpc proxy may forward.
        """
        return self.config.rpc_allow_list

    # pylint: disable=unused-argument
    @Core.receiver('onsetup')
    def onsetup(self, sender, **kwargs):
        self.vip.rpc.export(self._auto_allow_csr, 'auto_allow_csr')
        self.vip.rpc.export(self._is_auto_allow_csr, 'is_auto_allow_csr')

    def _is_auto_allow_csr(self):
        return self._csr_endpoints.auto_allow_csr

    def _auto_allow_csr(self, auto_allow_csr):
        self._csr_endpoints.auto_allow_csr = auto_allow_csr

    def remove_unconnnected_routes(self):
        peers = self.vip.peerlist().get()

        for p in self.peer_routes:
            if p not in peers:
                del self.peer_routes[p]

    @RPC.export
    def get_user_claims(self, bearer):
        from ..web import get_user_claim_from_bearer
        if self.ssl_cert is not None:
            claims = get_user_claim_from_bearer(bearer,
                                                tls_public_key=CertWrapper.get_cert_public_key(self.ssl_cert))
        elif self.config.secret_key is not None:
            claims = get_user_claim_from_bearer(bearer, web_secret_key=self.config.secret_key.get_secret_value())

        else:
            raise ValueError("Configuration error secret key or web ssl cert must be not None.")

        return claims if claims.get('grant_type') == 'access_token' else {}

    @RPC.export
    def websocket_send(self, endpoint, message):
        _log.debug("Sending data to {} with message {}".format(endpoint,
                                                               message))
        self.appContainer.websocket_send(endpoint, message)

    @RPC.export
    def print_websocket_clients(self):
        _log.debug(self.appContainer.endpoint_clients)

    @RPC.export
    def get_bind_web_address(self):
        return self.config.bind_address

    @RPC.export
    def get_volttron_central_address(self):
        """Return address of external Volttron Central

        Note: this only applies to Volttron Central agents that are
        running on a different platform.
        """
        return self.volttron_central_address

    @RPC.export
    def register_endpoint(self, endpoint, res_type):
        """
        RPC method to register a dynamic route.

        :param endpoint:
        :return:
        """
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer
        _log.debug('Registering route with endpoint: {}'.format(endpoint))
        _log.debug('Route is associated with peer: {}'.format(identity))

        if _path_is_reserved(endpoint):
            _log.warning(f"Peer {identity} attempted to register reserved endpoint {endpoint}.")
            raise ReservedRouteError(f"Endpoint {endpoint} is reserved for the platform web service.")

        if endpoint in self.endpoints:
            _log.error("Attempting to register an already existing endpoint.")
            _log.error("Ignoring registration.")
            raise DuplicateEndpointError(
                "Endpoint {} is already an endpoint".format(endpoint))

        self.endpoints[endpoint] = (identity, res_type)

    @RPC.export
    def register_agent_route(self, regex, fn):
        """ Register an agent route to an exported function.

        When a http request is executed and matches the passed regular
        expression then the function on peer is executed.
        """
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer

        _log.info(
            'Registering agent route expression: {} peer: {} function: {}'
                .format(regex, identity, fn))

        # TODO: inspect peer for function

        compiled = re.compile(regex)
        if _regex_covers_reserved(compiled):
            _log.warning(f"Peer {identity} attempted to register agent route {regex} covering a reserved path.")
            raise ReservedRouteError(f"Route {regex} would shadow a path reserved for the platform web service.")
        self.peer_routes[identity].append(compiled)
        _insert_peer_route(self.registered_routes, (compiled, 'peer_route', (identity, fn)))

    @RPC.export
    def unregister_all_agent_routes(self):
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer

        _log.info('Unregistering agent routes for: {}'.format(identity))
        for regex in self.peer_routes[identity]:
            out = [cp for cp in self.registered_routes if cp[0] != regex]
            self.registered_routes = out
        del self.peer_routes[identity]
        for regex in self.path_routes[identity]:
            out = [cp for cp in self.registered_routes if cp[0] != regex]
            self.registered_routes = out
        del self.path_routes[identity]

        endpoints = self.endpoints.copy()
        endpoints = {i:endpoints[i] for i in endpoints if endpoints[i][0] != identity}
        self.endpoints = endpoints

    def agent_web_root(self, identity: str) -> Path:
        """Return the one directory from which the agent with this identity may publish static files.

        With ``web-root-dir`` configured this is ``<web_root_dir>/<identity>``; otherwise it is
        ``<VOLTTRON_HOME>/agents/<identity>/data/web-root``. The directory is not created here and need not exist
        until the agent registers it.

        :raises ValueError: if the identity is not a single clean path component, so it cannot be used to name
            a directory without the risk of selecting a different one.
        """
        if not identity or Path(identity).name != identity or identity in ('.', '..'):
            raise ValueError(f'Cannot derive a web root for identity {identity!r}.')
        if self.config.web_root_dir is not None:
            parent = self.config.web_root_dir
            web_root = parent / identity
        else:
            parent = Path(self.config.volttron_home) / 'agents' / identity / 'data'
            web_root = parent / AGENT_WEB_ROOT_DIRNAME
        resolved = web_root.resolve()
        if resolved.parent != parent.resolve():
            # A symlink or similar has moved the allotted directory somewhere else. Refuse rather than follow.
            raise ValueError(f'Web root for identity {identity!r} does not resolve to a child of {parent}.')
        return resolved

    @RPC.export
    def get_web_root(self) -> str:
        """Return the directory from which the calling agent may publish static files via register_path_route.

        The directory is not created. Place files in it, then call register_path_route with the URL pattern they
        should be served under.
        """
        identity = self.vip.rpc.context.vip_message.peer
        return str(self.agent_web_root(identity))

    @RPC.export
    def register_path_route(self, regex, root_dir=None):
        """Serve the calling agent's web root for requests matching regex.

        Static files are always served from the agent's allotted web root (see get_web_root); the agent cannot
        choose another directory. ``root_dir`` is accepted for compatibility with the client subsystem and, when
        given, must name that same directory. Returns the directory that was registered.
        """
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer

        _log.info(f'Registering web path route from {identity} regex: {regex} dir: {root_dir}')

        try:
            web_root = self.agent_web_root(identity)
        except ValueError as e:
            _log.warning(f'Refused web path route from {identity}: {e}')
            raise

        if root_dir is not None and Path(root_dir).expanduser().resolve() != web_root:
            _log.warning(f'Refused web path route from {identity}: {root_dir!r} is not its web root {web_root}.')
            raise ValueError(f"root_dir must be the agent's web root {web_root} (or be omitted): {root_dir!r}")

        # Defense in depth: the web root is derived from a per-identity path and can never be the filesystem
        # root, but the serve-time containment check degenerates to a no-op for '/' so refuse it explicitly.
        if web_root == Path(web_root.anchor):
            raise ValueError(f"root_dir must not be the filesystem root: {root_dir!r}")

        if not web_root.is_dir():
            _log.warning(f'Refused web path route from {identity}: web root {web_root} is not an existing directory.')
            raise ValueError(f"root_dir must be an existing directory: {web_root}")

        canonical_root = web_root

        compiled = re.compile(regex)
        self.path_routes[identity].append(compiled)
        # in order for this agent to pass against the default route we want this
        # to be before the last route which will resolve to .*
        self.registered_routes.insert(len(self.registered_routes) - 1, (compiled, 'path', str(canonical_root)))
        return str(canonical_root)

    @RPC.export
    def register_websocket(self, endpoint):
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer

        _log.debug('Caller identity: {}'.format(identity))
        _log.debug('REGISTERING ENDPOINT: {}'.format(endpoint))
        if _path_is_reserved(endpoint):
            _log.warning(f"Peer {identity} attempted to register reserved websocket endpoint {endpoint}.")
            raise ReservedRouteError(f"Endpoint {endpoint} is reserved for the platform web service.")
        if self.appContainer:
            self.appContainer.create_ws_endpoint(endpoint, identity)
        else:
            _log.error('Attempting to register endpoint without web'
                       'subsystem initialized')
            raise AttributeError("self does not contain"
                                 " attribute appContainer")

    @RPC.export
    def unregister_websocket(self, endpoint):
        # Get calling identity from whom the request came from
        identity = self.vip.rpc.context.vip_message.peer

        _log.debug('Caller identity: {}'.format(identity))
        self.appContainer.destroy_ws_endpoint(endpoint)

    @RPC.export
    def get_packaged_configs(self) -> dict:
        import importlib.metadata
        import json

        package_configs = {}
        for dist in importlib.metadata.distributions():
            name = dist.metadata.get("Name")
            if name:
                name_lower = name.lower()
                if name_lower.startswith("volttron-") or name_lower.startswith("volttron_"):
                    configs = {}
                    if dist.files:
                        for file_ref in dist.files:
                            if "example" in file_ref.name and file_ref.name.endswith((".config", ".json")):
                                try:
                                    content = file_ref.read_text()
                                    filename = os.path.basename(file_ref.name)
                                    if filename.endswith(".json"):
                                        try:
                                            configs[filename] = json.loads(content)
                                        except Exception:
                                            configs[filename] = content
                                    else:
                                        configs[filename] = content
                                except Exception as e:
                                    _log.error(f"Failed to read file {file_ref.name} from distribution {name}: {e}")
                    if configs:
                        package_configs[name] = configs
        return package_configs

    def _redirect_index(self, env, start_response, data=None):
        """ Redirect to the index page.
        @param env:
        @param start_response:
        @param data:
        @return:
        """
        start_response('302 Found', [('Location', '/index.html')])
        return [b'1']

    def app_routing(self, env, start_response):
        """
        The main routing function that maps the incoming request to a response.

        Depending on the registered routes map the request data onto an rpc
        function or a specific named file.
        """
        path_info = env['PATH_INFO']

        if path_info.startswith('/http://'):
            path_info = path_info[path_info.index('/', len('/http://')):]

        # only expose a partial list of the env variables to the registered
        # agents (never credentials, see PEER_ENV_KEYS).
        data = env['wsgi.input'].read().decode('utf-8')
        passenv = {k: env[k] for k in PEER_ENV_KEYS if k in env}

        _log.debug('path_info is: {}'.format(path_info))
        # Get the peer responsible for dealing with the endpoint.  If there
        # isn't a peer then fall back on the other methods of routing.
        (peer, res_type) = self.endpoints.get(path_info, (None, None))
        _log.debug('Peer path_info is associated with: {}'.format(peer))

        if self.is_json_content(env):
            data = jsonapi.loads(data)

        # if we have a peer then we expect to call that peer's web subsystem
        # callback to perform whatever is required of the method.
        if peer:
            _log.debug('Calling peer {} back for {}'.format(peer, path_info))
            res = self.vip.rpc.call(peer, 'route.callback',
                                    passenv, data).get(timeout=60)

            if res_type == "jsonrpc":
                return self.create_response(res, start_response)
            elif res_type == "raw":
                return self.create_raw_response(res, start_response)

        env['JINJA2_TEMPLATE_ENV'] = tplenv

        # if ws4pi.socket is set then this connection is a web socket
        # and so we return the websocket response.

        if 'ws4py.socket' in env:
            return env['ws4py.socket'](env, start_response)

        for k, t, v in self.registered_routes:
            if k.match(path_info):
                _log.debug("MATCHED:\npattern: {}, path_info: {}\n v: {}"
                           .format(k.pattern, path_info, v))
                _log.debug('registered route t is: {}'.format(t))
                if t == 'callable':  # Generally for locally called items.
                    # Changing signature of the "locally" called points to return
                    # a Response object. Our response object then will in turn
                    # be processed and the response will be written back to the
                    # calling client.
                    try:
                        retvalue = v(env, start_response, data)
                    except TypeError:
                        response = v(env, data)
                        return response(env, start_response)
                        # retvalue = self.process_response(start_response, v(env, data))

                    if isinstance(retvalue, Response):
                        return retvalue(env, start_response)
                    else:
                        return retvalue[0]

                elif t == 'peer_route':  # RPC calls from agents on the platform
                    _log.debug('Matched peer_route with pattern {}'.format(
                        k.pattern))
                    peer, fn = (v[0], v[1])
                    res = self.vip.rpc.call(peer, fn, passenv, data).get(
                        timeout=120)
                    return self.create_response(res, start_response)

                elif t == 'path':  # File service from agents on the platform.
                    if path_info == '/':
                        return self._redirect_index(env, start_response)
                    try:
                        server_path = _safe_path_within_root(v, path_info)
                    except HiddenPathError:
                        # Hidden files (.git, .env, .htpasswd) are never served; answer as if absent.
                        start_response('404 Not Found', [('Content-Type', 'text/html')])
                        return [b'<h1>Not Found</h1>']
                    except (ValueError, OSError):
                        # ValueError: the resolved candidate escaped root
                        # (traversal, absolute-path, prefix-sibling, symlink).
                        # OSError: Path.resolve() on a broken symlink or a
                        # permission error. Both are treated as 403 (fail-closed)
                        # rather than propagating a 500.
                        # VO-005/H2 warning log preserved: a rejection is a
                        # security-relevant event and must stay observable.
                        _log.warning(
                            'Path traversal attempt blocked: %s not under root %s',
                            path_info, v,
                        )
                        start_response('403 Forbidden', [('Content-Type', 'text/html')])
                        return [b'<h1>403 Forbidden</h1>']
                    _log.debug('Serverpath: {}'.format(server_path))
                    return self._sendfile(env, start_response, server_path)

        start_response('404 Not Found', [('Content-Type', 'text/html')])
        return [b'<h1>Not Found</h1>']

    def is_json_content(self, env):
        ct = env.get('CONTENT_TYPE')
        if ct is not None and 'application/json' in ct:
            return True
        return False

    def process_response(self, start_response, response):
        # if we are using the original response, then morph it into a werkzueg response.
        # response = PlatformWebService.convert_response_to_werkzueg(response)
        # return response()
        # process the response
        start_response(response.status, response.headers)

        if isinstance(response.content, str):
            return [response.content.encode('utf-8')]
        return [response.content]

    def create_raw_response(self, res, start_response):
        # If this is a tuple then we know we are going to have a response
        # and a headers portion of the data.
        if isinstance(res, tuple) or isinstance(res, list):
            if len(res) == 1:
                status, = res
                headers = ()
            elif len(res) == 2:
                headers = ()
                status, response = res
            elif len(res) == 3:
                status, response, headers = res
            else:
                raise Exception("Couldn't process raw response {}".format(res))
            start_response(status.encode('utf-8'), headers)
            return [base64.b64decode(response)]
        else:
            start_response("500 Programming Error",
                           [('Content-Type', 'text/html')])
            _log.error("Invalid length of response tuple (must be 1-3)")
            return [b'Invalid response tuple (must contain 1-3 elements)']

    def create_response(self, res, start_response):

        # Dictionaries are going to be treated as if they are meant to be json
        # serialized with Content-Type of application/json
        if isinstance(res, dict):
            # Note this is specific to volttron central agent and should
            # probably not be at this level of abstraction.
            if 'error' in res.keys():
                if res['error']['code'] == UNAUTHORIZED:
                    start_response('401 Unauthorized', [
                        ('Content-Type', 'text/html')])
                    message = res['error']['message']
                    code = res['error']['code']
                    return ['<h1>{}</h1>\n<h2>CODE:{}</h2>'.format(message, code).encode('utf-8')]

            start_response('200 OK',
                           [('Content-Type', 'application/json')])
            return [jsonapi.dumpb(res)]
        elif isinstance(res, list):
            _log.debug('list implies [content, headers] or [status, content, headers]')
            if len(res) == 2:
                start_response('200 OK',
                               res[1])
                return res[0]
            elif len(res) == 3:
                start_response(res[0], res[2])
                if isinstance(res[1], str):
                    return [res[1].encode('utf-8')]
                return [res[1]]

        # If this is a tuple then we know we are going to have a response
        # and a headers portion of the data.
        if isinstance(res, tuple) or isinstance(res, list):
            if len(res) != 2:
                start_response("500 Programming Error",
                               [('Content-Type', 'text/html')])
                _log.error("Invalid length of response tuple (must be 2)")
                return [b'Invalid response tuple (must contain 2 elements)']

            response, headers = res
            header_dict = dict(headers)
            if header_dict.get('Content-Encoding', None) == 'gzip':
                gzip_compress = zlib.compressobj(9, zlib.DEFLATED,
                                                 zlib.MAX_WBITS | 16)
                data = gzip_compress.compress(response) + gzip_compress.flush()
                start_response('200 OK', headers)
                return [data]
            else:
                return [response]
        else:
            start_response('200 OK',
                           [('Content-Type', 'application/json')])
            return [jsonapi.dumpb(res)]

    def _sendfile(self, env, start_response, filename):
        from wsgiref.util import FileWrapper
        status = '200 OK'
        _log.debug('SENDING FILE: {}'.format(filename))
        guess = mimetypes.guess_type(filename)[0]
        _log.debug('MIME GUESS: {}'.format(guess))

        basename = os.path.dirname(filename)

        if not os.path.exists(basename):
            start_response('404 Not Found', [('Content-Type', 'text/html')])
            return [b'<h1>Not Found</h1>']
        elif not os.path.isfile(filename):
            # Directories, sockets, devices and anything else that is not a regular file are never served.
            start_response('404 Not Found', [('Content-Type', 'text/html')])
            return [b'<h1>Not Found</h1>']

        if not guess:
            guess = 'text/plain'

        response_headers = [
            ('Content-type', guess),
            # Browsers must honour the declared type and not re-interpret, e.g., a text file as a script.
            ('X-Content-Type-Options', 'nosniff'),
        ]
        start_response(status, response_headers)

        return FileWrapper(open(filename, 'rb'))

    @Core.receiver('onstart')
    def startupagent(self, sender, **kwargs):
        ssl_key = self.config.ssl_key
        ssl_cert = self.config.ssl_cert
        rpc_caller = self.vip.rpc
        if self.config.bind_address.scheme == 'https':
            if ssl_key is None or ssl_cert is None:
                base_filename = ClientContext.get_fq_identity(self.core.identity) + "-server"
                ssl_cert = self._certs.cert_file(base_filename)
                ssl_key = self._certs.private_key_file(base_filename)

                if not os.path.isfile(ssl_cert) or not os.path.isfile(ssl_key):
                    self._certs.create_signed_cert_files(base_filename, cert_type='server')

            if ssl_key is not None and ssl_cert is not None and self._admin_endpoints is None:
                self._admin_endpoints = AdminEndpoints(ssl_public_key=CertWrapper.get_cert_public_key(ssl_cert),
                                                       rpc_caller=rpc_caller)
        else:
            self._admin_endpoints = AdminEndpoints(rpc_caller=rpc_caller)
        _log.info(f'Starting web server binding to {self.config.bind_address}.')

        # Register the admin endpoints regardless of whether there is an ssl context
        # or not.
        for rt in self._admin_endpoints.get_routes():
            self.registered_routes.append(rt)

        # Register VUI endpoints:
        self._vui_endpoints = VUIEndpoints(self)
        self.registered_routes.extend(self._vui_endpoints.get_routes())

        # Allow authentication endpoint from any https connection
        if self.config.bind_address.scheme == 'https':
            ssl_private_key = CertWrapper.get_private_key(ssl_key)
            ssl_public_key = CertWrapper.get_cert_public_key(self.config.ssl_cert)
            for rt in AuthenticateEndpoints(tls_private_key=ssl_private_key, tls_public_key=ssl_public_key).get_routes():
                self.registered_routes.append(rt)
        else:
            # We don't have a private ssl key if we aren't using ssl.
            for rt in AuthenticateEndpoints(web_secret_key=self.config.secret_key.get_secret_value()).get_routes():
                self.registered_routes.append(rt)

        static_dir = os.path.join(os.path.dirname(__file__), "static")
        self.registered_routes.append((re.compile('^/.*$'), 'path', static_dir))

        port = int(self.config.bind_address.port)

        self.appContainer = WebApplicationWrapper(self, self.config.bind_address.host, port)
        if ssl_key and ssl_cert:
            svr = WSGIServer(((self.config.bind_address.host), port), self.appContainer,
                             certfile=ssl_cert,
                             keyfile=ssl_key)
        else:
            svr = WSGIServer(((self.config.bind_address.host), port), self.appContainer)
        self._server_greenlet = gevent.spawn(svr.serve_forever)

    @Core.receiver('onstop')
    def onstop(self, sender, **kwargs):
        _log.debug("Stopping web agent.")
        if not self._server_greenlet.dead:
            self._server_greenlet.join(timeout=10)
