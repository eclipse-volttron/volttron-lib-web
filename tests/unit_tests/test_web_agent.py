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

"""
Unit tests for PlatformWebService route registration and static file serving.

Static file routes registered through ``register_path_route`` must never serve a file
outside the registered root (GHSA-5h47-g9cc-gfg8). Escape attempts must yield a 403 AND
must not return the out-of-root bytes, so every escape test asserts both sides.

An agent may only ever register its own allotted web root: ``<VOLTTRON_HOME>/agents/<identity>/data/web-root``
by default, or ``<web-root-dir>/<identity>`` when the operator configures ``web-root-dir``. The fixture peer is
"foo" (see web_utils.set_rpc_caller), so its default web root lives inside the test VOLTTRON_HOME.
"""
import logging
import re

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from volttron.client.known_identities import AUTH
from volttron.services.web.platform_web_service import (PlatformWebService, WebServiceConfig, HiddenPathError,
                                                        _safe_path_within_root)
from volttron.types.auth import AuthException
from volttron.utils import jsonrpc

from web_utils import get_test_web_env, mock_platform_web_service, set_rpc_caller

SECRET = "OUT-OF-ROOT SECRET"
EVIL = "SIBLING EVIL"
LEGITIMATE = "LEGITIMATE CONTENT"


PEER = "foo"


def _populate_web_root(root: Path) -> dict:
    """Create a small web root with a known file, plus out-of-root traps beside it that must never be served."""
    root.mkdir(parents=True)
    (root / "index.html").write_text(LEGITIMATE, encoding="utf-8")
    assets = root / "assets"
    assets.mkdir()
    (assets / "style.css").write_text("body{color:red}", encoding="utf-8")
    (root / ".hidden.txt").write_text("HIDDEN", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text("HIDDEN GIT CONFIG", encoding="utf-8")

    data_dir = root.parent
    # File outside root but inside the agent's data directory: the rest of data/ must stay private.
    secret = data_dir / "secret.txt"
    secret.write_text(SECRET, encoding="utf-8")

    # Sibling directory whose name starts with the root's name. A naive
    # str.startswith containment check would admit it.
    sibling_dir = data_dir / (root.name + "EVIL")
    sibling_dir.mkdir()
    (sibling_dir / "evil.txt").write_text(EVIL, encoding="utf-8")

    return {"root": root, "index": root / "index.html", "css": assets / "style.css",
            "secret": secret, "sibling_dir": sibling_dir, "tmp": data_dir}


@pytest.fixture()
def web_root(mock_platform_web_service):
    """The fixture peer's default web root, populated, inside the test VOLTTRON_HOME."""
    return _populate_web_root(mock_platform_web_service.agent_web_root(PEER))


def _route(pws, path_info):
    """Run one request through app_routing; return (status, body)."""
    start_response = MagicMock()
    data = pws.app_routing(get_test_web_env(path_info), start_response)
    body = b"".join(data).decode("utf-8", errors="replace")
    return start_response.call_args[0][0], body


def _assert_forbidden_no_leak(pws, path_info, forbidden_content):
    status, body = _route(pws, path_info)
    assert "403 Forbidden" in status, f"Expected 403 for {path_info!r}, got {status}"
    assert forbidden_content not in body, f"Out-of-root content leaked for {path_info!r}"


def test_register_routes(mock_platform_web_service, web_root):
    pws = mock_platform_web_service
    # root_dir may be given (and must then be the agent's web root) or omitted; either way the web root is used.
    assert pws.register_path_route(r"/.*", str(web_root["root"])) == str(web_root["root"].resolve())
    assert pws.register_path_route(r"/flubber") == str(web_root["root"].resolve())

    # Roots are resolved to absolute directories so containment checks are unambiguous.
    assert len(pws.registered_routes) == 2
    for regex, route_type, root_dir in pws.registered_routes:
        assert route_type == 'path'
        assert Path(root_dir).is_absolute()
        assert root_dir == str(web_root["root"].resolve())

    status, body = _route(pws, "/index.html")
    assert "200 OK" in status
    assert body == LEGITIMATE

    # Rooted traversal above the root is forbidden.
    _assert_forbidden_no_leak(pws, "/../secret.txt", SECRET)

    # An un-rooted relative path does not match any route and must not serve anything.
    status, body = _route(pws, "../secret.txt")
    assert "200 OK" not in status
    assert SECRET not in body


class TestHappyPath:
    def test_in_root_subdir_file_serves_correct_content(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        status, body = _route(pws, "/assets/style.css")
        assert "200 OK" in status
        assert body == "body{color:red}"

    def test_root_request_redirects_to_index(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        start_response = MagicMock()
        pws.app_routing(get_test_web_env("/"), start_response)
        status, headers = start_response.call_args[0]
        assert "302" in status
        assert ('Location', '/index.html') in headers

    def test_symlinked_root_serves_from_real_location(self, mock_platform_web_service, web_root):
        """A root that is itself a symlink is canonicalized; files under the real
        directory serve, and traversal out of it is still blocked."""
        sym_root = web_root["tmp"] / "sym_webroot"
        sym_root.symlink_to(web_root["root"])
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(sym_root))

        assert pws.registered_routes[0][2] == str(web_root["root"].resolve())
        status, body = _route(pws, "/index.html")
        assert "200 OK" in status
        assert body == LEGITIMATE
        _assert_forbidden_no_leak(pws, "/../secret.txt", SECRET)


class TestEscapePaths:
    def test_dotdot_traversal_rooted(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        _assert_forbidden_no_leak(pws, "/../secret.txt", SECRET)

    def test_dotdot_traversal_logs_warning(self, mock_platform_web_service, web_root, caplog):
        """A containment rejection is a security-relevant event and must be logged."""
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        with caplog.at_level(logging.WARNING, logger="volttron.services.web.platform_web_service"):
            _assert_forbidden_no_leak(pws, "/../secret.txt", SECRET)
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("Path traversal attempt blocked" in w for w in warnings), warnings

    def test_prefix_sibling_escape(self, mock_platform_web_service, web_root):
        """'webrootEVIL' starts with 'webroot' but is not inside it."""
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        _assert_forbidden_no_leak(pws, "/../webrootEVIL/evil.txt", EVIL)

    def test_symlink_outside_root_blocked(self, mock_platform_web_service, web_root):
        """A symlink inside root that points outside root is blocked at serve time."""
        link_path = web_root["root"] / "link_to_secret.txt"
        link_path.symlink_to(web_root["secret"])
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        _assert_forbidden_no_leak(pws, "/link_to_secret.txt", SECRET)

    def test_absolute_path_is_neutralized(self, mock_platform_web_service, web_root):
        """An absolute PATH_INFO is joined under root rather than replacing it, so the
        original out-of-root file can never be reached."""
        root = str(web_root["root"])
        neutralized = _safe_path_within_root(root, str(web_root["secret"]))
        assert neutralized.startswith(str(Path(root).resolve()))
        assert neutralized != str(web_root["secret"].resolve())

        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", root)
        status, body = _route(pws, str(web_root["secret"]))
        assert "200 OK" not in status
        assert SECRET not in body

    def test_oserror_during_resolve_returns_403_not_500(self, mock_platform_web_service, web_root):
        """Path.resolve() can raise OSError (broken symlink, permissions). Fail closed."""
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        with patch("volttron.services.web.platform_web_service.Path.resolve",
                   side_effect=OSError("simulated broken symlink")):
            status, body = _route(pws, "/index.html")
        assert "403 Forbidden" in status
        assert LEGITIMATE not in body


class TestServeTimeHardening:
    def test_hidden_file_is_404_not_served(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*")
        status, body = _route(pws, "/.hidden.txt")
        assert "404" in status
        assert "HIDDEN" not in body

    def test_hidden_directory_segment_is_404_not_served(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*")
        status, body = _route(pws, "/.git/config")
        assert "404" in status
        assert "HIDDEN GIT CONFIG" not in body

    def test_directory_is_404(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*")
        status, body = _route(pws, "/assets")
        assert "404" in status

    def test_served_file_has_nosniff_header(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        pws.register_path_route(r"/.*")
        start_response = MagicMock()
        pws.app_routing(get_test_web_env("/assets/style.css"), start_response)
        status, headers = start_response.call_args[0]
        assert "200 OK" in status
        assert ('X-Content-Type-Options', 'nosniff') in headers


class TestSafePathHelper:
    def test_hidden_segments_raise_hidden_path_error(self, web_root):
        root = str(web_root["root"])
        for p in (".hidden.txt", "/.git/config", "assets/.secret"):
            with pytest.raises(HiddenPathError):
                _safe_path_within_root(root, p)

    def test_rejects_relative_escapes(self, web_root):
        root = str(web_root["root"])
        for p in ("../secret.txt", "../../etc/passwd", "assets/../../secret.txt"):
            with pytest.raises(ValueError):
                _safe_path_within_root(root, p)

    def test_allows_in_root_paths(self, web_root):
        root = str(web_root["root"])
        assert _safe_path_within_root(root, "index.html") == str(web_root["index"].resolve())
        assert _safe_path_within_root(root, "/index.html") == str(web_root["index"].resolve())
        assert _safe_path_within_root(root, "assets/style.css") == str(web_root["css"].resolve())


class TestRegistrationRejection:
    """register_path_route must reject anything but the caller's own existing web root and insert NO route."""

    def test_filesystem_root_rejected(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError):
            pws.register_path_route(r"/.*", "/")
        assert pws.registered_routes == routes_before

    def test_other_directory_rejected(self, mock_platform_web_service, web_root, tmp_path):
        """A perfectly valid directory that is not the caller's web root is refused."""
        pws = mock_platform_web_service
        other = tmp_path / "other_root"
        other.mkdir()
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="web root"):
            pws.register_path_route(r"/.*", str(other))
        assert pws.registered_routes == routes_before

    def test_sibling_inside_data_dir_rejected(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="web root"):
            pws.register_path_route(r"/.*", str(web_root["sibling_dir"]))
        assert pws.registered_routes == routes_before

    def test_subdirectory_of_web_root_rejected(self, mock_platform_web_service, web_root):
        pws = mock_platform_web_service
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="web root"):
            pws.register_path_route(r"/.*", str(web_root["root"] / "assets"))
        assert pws.registered_routes == routes_before

    def test_web_root_as_file_rejected(self, mock_platform_web_service):
        pws = mock_platform_web_service
        web_root = pws.agent_web_root(PEER)
        web_root.parent.mkdir(parents=True)
        web_root.write_text("I am a file", encoding="utf-8")
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="existing directory"):
            pws.register_path_route(r"/.*")
        assert pws.registered_routes == routes_before

    def test_missing_web_root_rejected(self, mock_platform_web_service):
        pws = mock_platform_web_service
        assert not pws.agent_web_root(PEER).exists()
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="existing directory"):
            pws.register_path_route(r"/.*")
        with pytest.raises(ValueError, match="existing directory"):
            pws.register_path_route(r"/.*", str(pws.agent_web_root(PEER)))
        assert pws.registered_routes == routes_before

    def test_valid_directory_accepted_before_default_route(self, mock_platform_web_service, web_root):
        """A valid root inserts exactly one canonicalized route, ahead of the catch-all."""
        pws = mock_platform_web_service
        static_dir = web_root["tmp"] / "static"
        static_dir.mkdir()
        pws.registered_routes.append((re.compile('^/.*$'), 'path', str(static_dir)))

        pws.register_path_route(r"/valid/.*")

        assert len(pws.registered_routes) == 2
        regex, route_type, root_dir = pws.registered_routes[0]
        assert route_type == 'path'
        assert root_dir == str(web_root["root"].resolve())
        assert pws.registered_routes[-1][2] == str(static_dir)

    @pytest.mark.parametrize("identity", ["", ".", "..", "a/b", "../foo", "/etc"])
    def test_unusable_identity_rejected(self, mock_platform_web_service, identity):
        pws = mock_platform_web_service
        with pytest.raises(ValueError, match="identity"):
            pws.agent_web_root(identity)
        set_rpc_caller(pws, peer=identity)
        with pytest.raises(ValueError):
            pws.get_web_root()
        with pytest.raises(ValueError):
            pws.register_path_route(r"/.*")


class TestWebRootAllotment:
    def test_default_web_root_is_inside_agent_data_dir(self, mock_platform_web_service):
        pws = mock_platform_web_service
        expected = Path(pws.config.volttron_home).resolve() / "agents" / PEER / "data" / "web-root"
        assert pws.agent_web_root(PEER) == expected
        # Does not need to exist to be reported.
        assert not expected.exists()
        assert pws.get_web_root() == str(expected)

    def test_get_web_root_is_exported(self, mock_platform_web_service):
        assert 'get_web_root' in mock_platform_web_service.vip.rpc.get_exports()

    def test_get_web_root_is_per_caller(self, mock_platform_web_service):
        pws = mock_platform_web_service
        set_rpc_caller(pws, peer="bar")
        assert pws.get_web_root().endswith("/agents/bar/data/web-root")

    def test_symlinked_web_root_pointing_elsewhere_rejected(self, mock_platform_web_service, tmp_path):
        """The allotted directory itself must be a real child of its parent, not a link out of it."""
        pws = mock_platform_web_service
        web_root = pws.agent_web_root(PEER)
        web_root.parent.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        web_root.symlink_to(elsewhere)
        with pytest.raises(ValueError, match="does not resolve"):
            pws.agent_web_root(PEER)
        with pytest.raises(ValueError):
            pws.register_path_route(r"/.*")

    def test_configured_web_root_dir_replaces_default(self, mock_platform_web_service, tmp_path):
        pws = mock_platform_web_service
        shared = tmp_path / "shared-web"
        shared.mkdir()
        pws.config.web_root_dir = shared
        assert pws.config.web_root_dir == shared.resolve()
        assert pws.agent_web_root(PEER) == shared.resolve() / PEER
        assert pws.get_web_root() == str(shared.resolve() / PEER)

        files = _populate_web_root(shared / PEER)
        assert pws.register_path_route(r"/.*") == str(files["root"].resolve())
        status, body = _route(pws, "/index.html")
        assert "200 OK" in status and body == LEGITIMATE
        _assert_forbidden_no_leak(pws, "/../secret.txt", SECRET)

    def test_default_web_root_refused_once_web_root_dir_configured(self, mock_platform_web_service, web_root,
                                                                   tmp_path):
        pws = mock_platform_web_service
        shared = tmp_path / "shared-web"
        shared.mkdir()
        pws.config.web_root_dir = shared
        routes_before = list(pws.registered_routes)
        with pytest.raises(ValueError, match="web root"):
            pws.register_path_route(r"/.*", str(web_root["root"]))
        assert pws.registered_routes == routes_before


class TestWebRootDirConfig:
    KW = dict(bind_web_address='http://127.0.0.1:8080', messagebus='zmq', web_secret_key='unit-test-secret-key')

    def test_valid_directory_is_resolved(self, tmp_path):
        vh = tmp_path / "vh"
        vh.mkdir()
        root = tmp_path / "web"
        root.mkdir()
        (tmp_path / "link").symlink_to(root)
        config = WebServiceConfig(volttron_home=vh, web_root_dir=str(tmp_path / "link"), **self.KW)
        assert config.web_root_dir == root.resolve()

    def test_absent_by_default(self, tmp_path):
        assert WebServiceConfig(volttron_home=tmp_path, **self.KW).web_root_dir is None

    def test_missing_directory_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="existing directory"):
            WebServiceConfig(volttron_home=tmp_path, web_root_dir=str(tmp_path / "nope"), **self.KW)

    def test_regular_file_rejected(self, tmp_path):
        f = tmp_path / "file"
        f.write_text("x")
        with pytest.raises(ValueError, match="existing directory"):
            WebServiceConfig(volttron_home=tmp_path, web_root_dir=str(f), **self.KW)

    def test_filesystem_root_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="filesystem root"):
            WebServiceConfig(volttron_home=tmp_path, web_root_dir="/", **self.KW)

    def test_volttron_home_rejected(self, tmp_path):
        vh = tmp_path / "vh"
        vh.mkdir()
        with pytest.raises(ValueError, match="VOLTTRON_HOME"):
            WebServiceConfig(volttron_home=vh, web_root_dir=str(vh), **self.KW)

    def test_ancestor_of_volttron_home_rejected(self, tmp_path):
        vh = tmp_path / "home" / "user" / ".volttron"
        vh.mkdir(parents=True)
        with pytest.raises(ValueError, match="VOLTTRON_HOME"):
            WebServiceConfig(volttron_home=vh, web_root_dir=str(tmp_path / "home" / "user"), **self.KW)
        with pytest.raises(ValueError, match="VOLTTRON_HOME"):
            WebServiceConfig(volttron_home=vh, web_root_dir=str(tmp_path), **self.KW)

    def test_directory_inside_volttron_home_allowed(self, tmp_path):
        vh = tmp_path / "vh"
        (vh / "web-root").mkdir(parents=True)
        config = WebServiceConfig(volttron_home=vh, web_root_dir=str(vh / "web-root"), **self.KW)
        assert config.web_root_dir == (vh / "web-root").resolve()


class TestProtectedRpcEnforcement:
    """register_path_route is exported over RPC and is intended to be a protected RPC.

    Modular VOLTTRON gates protected RPCs centrally: the RPC subsystem wraps the export
    with ``_add_auth_check`` which asks the auth service ``check_rpc_authorization``
    before running the method. These tests drive that wrapper around the real method.
    """

    def _checked_method(self, pws, auth_outcome, tmp_dir):
        rpc = pws.vip.rpc
        set_rpc_caller(pws, peer="test-agent", user="test-user", method="register_path_route")
        result = MagicMock()
        if isinstance(auth_outcome, Exception):
            result.get.side_effect = auth_outcome
        else:
            result.get.return_value = auth_outcome
        return rpc._add_auth_check(pws.register_path_route), result

    def test_register_path_route_is_exported(self, mock_platform_web_service):
        assert 'register_path_route' in mock_platform_web_service.vip.rpc.get_exports()

    def test_unauthorized_caller_rejected_no_route_inserted(self, mock_platform_web_service):
        pws = mock_platform_web_service
        valid_dir = pws.agent_web_root("test-agent")
        valid_dir.mkdir(parents=True)
        routes_before = list(pws.registered_routes)
        checked, result = self._checked_method(pws, AuthException("denied"), valid_dir)

        with patch.object(pws.vip.rpc, 'call', return_value=result) as call:
            with pytest.raises(jsonrpc.Error) as exc_info:
                checked(r"/uncap/.*", str(valid_dir))

        assert exc_info.value.code == jsonrpc.UNAUTHORIZED
        assert pws.registered_routes == routes_before
        call.assert_called_once()
        assert call.call_args[0][0] == AUTH
        kwargs = call.call_args[1]
        assert kwargs['method'] == "check_rpc_authorization"
        assert kwargs['identity'] == "test-user"
        assert kwargs['method_name'] == f"{pws.core.identity}.register_path_route"
        assert kwargs['method_args'] == {'regex': r"/uncap/.*", 'root_dir': str(valid_dir)}

    def test_authorized_caller_succeeds_and_route_inserted(self, mock_platform_web_service):
        pws = mock_platform_web_service
        valid_dir = pws.agent_web_root("test-agent")
        valid_dir.mkdir(parents=True)
        routes_before = len(pws.registered_routes)
        checked, result = self._checked_method(pws, True, valid_dir)

        with patch.object(pws.vip.rpc, 'call', return_value=result):
            checked(r"/cap/.*", str(valid_dir))

        assert len(pws.registered_routes) == routes_before + 1
        assert any(r[1] == 'path' and r[2] == str(valid_dir.resolve()) for r in pws.registered_routes)


def test_authenticate_route_debug_method_absent():
    """The monolithic _authenticate_route pprint()'d the WSGI env, including bearer
    tokens, to stdout. It must not reappear."""
    assert not hasattr(PlatformWebService, '_authenticate_route')
