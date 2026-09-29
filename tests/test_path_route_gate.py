# -*- coding: utf-8 -*-
"""
VO-007 / F8 regression tests: ungated register_path_route + path-traversal
escape at serve time (GHSA-5h47-g9cc-gfg8, CVSS 9.1).

Four test groups:
1. Happy-path: in-root file served correctly (content asserted, not just status).
2. Escape-path: traversal and sibling-prefix variants return 403 AND never return
   the out-of-root file bytes (two-sided assertion per data-invariants Rule 1).
3. Capability gate: register_path_route from a peer without the
   'register_path_route' capability must be rejected.
4. Registration rejection: root='/', root-as-file, OSError-at-serve-time.
"""
import pytest

from pathlib import Path
from unittest.mock import MagicMock, patch

from volttron.client.vip.agent import Agent
from volttron.services.web.platform_web_service import PlatformWebService, _safe_path_within_root
from volttrontesting.utils import AgentMock

from unit_tests.web_utils import get_test_web_env


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_platformweb_service() -> PlatformWebService:
    PlatformWebService.__bases__ = (AgentMock.imitate(Agent, Agent()),)
    platformweb = PlatformWebService(
        serverkey=MagicMock(),
        identity=MagicMock(),
        address=MagicMock(),
        bind_web_address=MagicMock(),
    )
    platformweb.vip.rpc.context.vip_message.peer.return_value = "test-agent"
    yield platformweb


@pytest.fixture()
def web_root(tmp_path):
    """Create a small web root with a known file and a sibling-directory trap."""
    root = tmp_path / "webroot"
    root.mkdir()

    # Legitimate file inside root.
    (root / "index.html").write_text("LEGITIMATE CONTENT", encoding="utf-8")
    subdir = root / "assets"
    subdir.mkdir()
    (subdir / "style.css").write_text("body{color:red}", encoding="utf-8")

    # File OUTSIDE root that must never be served.
    sibling_secret = tmp_path / "secret.txt"
    sibling_secret.write_text("OUT-OF-ROOT SECRET", encoding="utf-8")

    # Sibling directory whose name STARTS WITH the root dir name (prefix-sibling
    # bypass: /webrootEVIL/secret.txt must not be served via /EVIL/secret.txt
    # routed to root).
    sibling_dir = tmp_path / "webrootEVIL"
    sibling_dir.mkdir()
    (sibling_dir / "evil.txt").write_text("SIBLING EVIL", encoding="utf-8")

    yield {
        "root": root,
        "index": root / "index.html",
        "css": subdir / "style.css",
        "secret": sibling_secret,
        "sibling_dir": sibling_dir,
        "tmp": tmp_path,
    }


# ---------------------------------------------------------------------------
# Group 1: Happy-path serving
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_in_root_index_serves_correct_content(self, mock_platformweb_service, web_root):
        """In-root file: HTTP 200 and the exact file bytes returned."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))

        start_response = MagicMock()
        data = pws.app_routing(get_test_web_env("/index.html"), start_response)
        body = b"".join(data).decode("utf-8")

        assert "200 OK" in start_response.call_args[0]
        assert body == "LEGITIMATE CONTENT"

    def test_in_root_subdir_file_serves_correct_content(self, mock_platformweb_service, web_root):
        """Nested file in a sub-directory within root: 200 with correct bytes."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))

        start_response = MagicMock()
        data = pws.app_routing(get_test_web_env("/assets/style.css"), start_response)
        body = b"".join(data).decode("utf-8")

        assert "200 OK" in start_response.call_args[0]
        assert body == "body{color:red}"

    def test_static_dir_route_is_preserved(self, mock_platformweb_service, web_root):
        """The platform static-dir fallback route is registered as path type
        and serves legitimately (regression guard for VO-007 change)."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/myapp/.*", str(web_root["root"]))
        # The route inserted must be a path-type tuple with an absolute root.
        path_routes = [r for r in pws.registeredroutes if r[1] == 'path']
        assert len(path_routes) >= 1
        for _, rtype, rdir in path_routes:
            assert Path(rdir).is_absolute(), "All registered path roots must be absolute"


# ---------------------------------------------------------------------------
# Group 2: Escape-path blocking (two-sided: 403 status + out-of-root bytes absent)
# ---------------------------------------------------------------------------

class TestEscapePaths:
    """Each test asserts BOTH that a 403 is returned AND that the out-of-root
    file bytes are NOT present in the response body."""

    SECRET = "OUT-OF-ROOT SECRET"
    EVIL = "SIBLING EVIL"

    def _assert_forbidden_no_leak(self, pws, path_info, forbidden_content):
        start_response = MagicMock()
        data = pws.app_routing(get_test_web_env(path_info), start_response)
        body = b"".join(data).decode("utf-8", errors="replace")
        assert "403 Forbidden" in start_response.call_args[0], \
            f"Expected 403 for {path_info!r}, got {start_response.call_args}"
        assert forbidden_content not in body, \
            f"Out-of-root content leaked for {path_info!r}"

    def test_dotdot_traversal_rooted(self, mock_platformweb_service, web_root):
        """/../secret.txt must be 403 and must not leak secret bytes."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        self._assert_forbidden_no_leak(pws, "/../secret.txt", self.SECRET)

    def test_dotdot_traversal_logs_warning(self, mock_platformweb_service, web_root, caplog):
        """The VO-005/H2 warning log must still fire on a containment rejection.

        Two-sided per data-invariants Rule 1: the warning record is present
        AND the response stays a 403 with no out-of-root bytes leaked.
        """
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        path_info = "/../secret.txt"
        with caplog.at_level("WARNING", logger="volttron.platform.web.platform_web_service"):
            self._assert_forbidden_no_leak(pws, path_info, self.SECRET)

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any("Path traversal attempt blocked" in r.getMessage() for r in warnings), (
            "Expected a 'Path traversal attempt blocked' warning log on containment "
            f"rejection; got: {[r.getMessage() for r in warnings]}"
        )

    def test_dotdot_traversal_relative(self, mock_platformweb_service, web_root):
        """../secret.txt (no leading slash) must not serve out-of-root content."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        # app_routing normalises the path, but we verify the helper directly too.
        with pytest.raises(ValueError):
            _safe_path_within_root(str(web_root["root"]), "../secret.txt")

    def test_absolute_path_outside_root(self, mock_platformweb_service, web_root):
        """An absolute path_info is NEUTRALIZED by joining under root, not rejected.

        The helper strips the leading '/' and joins the remainder under root_dir so
        the resolved candidate is always inside root. The out-of-root file bytes must
        NOT appear in the response (two-sided assertion per data-invariants Rule 1).
        """
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))

        # Direct helper assertion: absolute path_info is neutralized, not escaped.
        root = str(web_root["root"])
        neutralized = _safe_path_within_root(root, str(web_root["secret"]))
        # Containment: the resolved result must be inside root, not at the original location.
        assert neutralized.startswith(str(Path(root).resolve())), (
            "Absolute path injection must be neutralized inside root, not routed to "
            "the original out-of-root path"
        )
        assert neutralized != str(web_root["secret"].resolve()), (
            "Neutralized path must differ from the original out-of-root secret path"
        )

        # Via app_routing: secret file bytes must not appear in the response body.
        # The neutralized path does not exist inside root, so the response is 404/empty,
        # but crucially the OUT-OF-ROOT bytes must not leak regardless of status code.
        start_response = MagicMock()
        data = pws.app_routing(
            get_test_web_env(str(web_root["secret"])), start_response
        )
        body = b"".join(data).decode("utf-8", errors="replace")
        assert self.SECRET not in body, (
            "Out-of-root secret bytes must not appear in response body for "
            "absolute path_info injection"
        )

    def test_prefix_sibling_escape(self, mock_platformweb_service, web_root):
        """webrootEVIL/evil.txt must not be served via a route rooted at webroot.

        This was the canonical prefix-sibling bypass: root.startswith(sibling_dir)
        is True because 'webroot' is a prefix of 'webrootEVIL'."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))
        # Build the path_info that would have matched under the old startswith check.
        # From 'webroot' root, '../webrootEVIL/evil.txt' escapes into the sibling.
        self._assert_forbidden_no_leak(pws, "/../webrootEVIL/evil.txt", self.EVIL)

    def test_symlink_outside_root_blocked(self, mock_platformweb_service, web_root):
        """A symlink inside root pointing outside root must be blocked at serve time."""
        link_target = web_root["secret"]
        link_path = web_root["root"] / "link_to_secret.txt"
        link_path.symlink_to(link_target)
        try:
            pws = mock_platformweb_service
            pws.register_path_route(r"/.*", str(web_root["root"]))
            self._assert_forbidden_no_leak(pws, "/link_to_secret.txt", self.SECRET)
        finally:
            link_path.unlink(missing_ok=True)

    def test_safe_path_within_root_helper_rejects_escape(self, web_root):
        """Unit-test the helper directly: ValueError on relative-path escapes.

        Relative paths that traverse above root raise ValueError. Absolute paths
        are NOT in this list: the helper neutralizes them by stripping the leading
        '/' and joining under root (see test_absolute_path_outside_root for that
        contract). Only paths that resolve OUTSIDE root after joining raise.
        """
        root = str(web_root["root"])
        # Relative traversal paths that escape root after resolution: must raise.
        escaping_paths = [
            "../secret.txt",
            "../../etc/passwd",
        ]
        for p in escaping_paths:
            with pytest.raises(ValueError):
                _safe_path_within_root(root, p)

        # Absolute path injection: neutralized (joined under root), must NOT raise.
        # Verify containment: the result is inside root, original file bytes cannot leak.
        abs_injection = str(web_root["secret"])
        neutralized = _safe_path_within_root(root, abs_injection)
        assert neutralized.startswith(str(Path(root).resolve())), (
            "Absolute path injection must be contained within root after neutralization"
        )

    def test_safe_path_within_root_helper_allows_valid(self, web_root):
        """Unit-test the helper directly: returns resolved path for in-root files."""
        root = str(web_root["root"])
        result = _safe_path_within_root(root, "index.html")
        assert result == str(web_root["index"].resolve())


# ---------------------------------------------------------------------------
# Group 3: Capability gate enforcement
# ---------------------------------------------------------------------------

class TestCapabilityGate:
    """register_path_route must carry the 'register_path_route' capability annotation
    so the VIP RPC layer rejects uncapable peers before the method body runs."""

    def test_rpc_allow_annotation_present(self):
        """The 'register_path_route' capability must be in the method's
        rpc.allow_capabilities annotation set (checked at decoration time).

        RPC.allow stores capabilities via volttron.platform.vip.agent.decorators.annotate
        into method._annotations['rpc.allow_capabilities'] as a set.
        """
        method = PlatformWebService.register_path_route
        # Capabilities are stored in the annotation set by RPC.allow.
        caps = getattr(method, '_annotations', {}).get('rpc.allow_capabilities', set())
        assert 'register_path_route' in caps, (
            "RPC method register_path_route must require 'register_path_route' "
            "capability; annotation not found."
        )

    def test_rpc_allow_annotation_via_introspection(self):
        """Alternative introspection path: verify the annotation set via MRO walk.

        annotate lives in volttron.platform.vip.agent.decorators, not in
        volttron.platform.messaging.utils. This test exercises the same storage
        contract from the reading side: walk __dict__ to find the raw function
        object and inspect its _annotations directly.
        """
        from volttron.platform.vip.agent.decorators import annotate  # noqa: F401 (documents the storage API)

        method = PlatformWebService.register_path_route
        # Walk MRO-resolution style: the annotation is set on the function object.
        caps = None
        for klass in PlatformWebService.__mro__:
            fn = klass.__dict__.get('register_path_route')
            if fn is not None:
                caps = getattr(fn, '_annotations', {}).get('rpc.allow_capabilities', None)
                break

        assert caps is not None and 'register_path_route' in caps, (
            "Capability 'register_path_route' not found via __dict__ introspection"
        )


# ---------------------------------------------------------------------------
# Group 4a: Registration rejection (root='/', root-as-file)
# ---------------------------------------------------------------------------

class TestRegistrationRejection:
    """register_path_route must reject over-broad or invalid roots at
    registration time and insert NO route when it does so
    (data-invariants Rule 1: assert the side-effect did NOT happen)."""

    def test_filesystem_root_rejected_raises(self, mock_platformweb_service):
        """root_dir='/' must raise ValueError: relative_to('/') succeeds for
        every path, so the serve-time containment would become a no-op."""
        pws = mock_platformweb_service
        before = len(pws.registeredroutes)

        with pytest.raises(ValueError, match="filesystem root"):
            pws.register_path_route(r"/.*", "/")

        # The route MUST NOT have been inserted (data-invariants Rule 1).
        assert len(pws.registeredroutes) == before, (
            "A rejected registration must not insert any route into registeredroutes"
        )

    def test_filesystem_root_no_route_inserted(self, mock_platformweb_service):
        """Explicit side-effect assertion: registeredroutes is unchanged after
        rejection of root='/'."""
        pws = mock_platformweb_service
        routes_before = list(pws.registeredroutes)

        try:
            pws.register_path_route(r"/bad/.*", "/")
        except ValueError:
            pass  # expected

        assert pws.registeredroutes == routes_before, (
            "registeredroutes must be identical after a rejected root='/' registration"
        )

    def test_root_as_file_rejected_raises(self, mock_platformweb_service, tmp_path):
        """A regular file passed as root_dir must raise ValueError.

        A file root is a boundary violation: the serve-time join logic
        assumes a directory, and a file root collapses containment."""
        pws = mock_platformweb_service
        regular_file = tmp_path / "notadir.txt"
        regular_file.write_text("I am a file", encoding="utf-8")
        before = len(pws.registeredroutes)

        with pytest.raises(ValueError, match="existing directory"):
            pws.register_path_route(r"/.*", str(regular_file))

        # No route must have been inserted.
        assert len(pws.registeredroutes) == before, (
            "A rejected root-as-file registration must not insert any route"
        )

    def test_root_as_file_no_route_inserted(self, mock_platformweb_service, tmp_path):
        """Side-effect assertion: registeredroutes is unchanged after root-as-file rejection."""
        pws = mock_platformweb_service
        regular_file = tmp_path / "notadir2.txt"
        regular_file.write_text("file", encoding="utf-8")
        routes_before = list(pws.registeredroutes)

        try:
            pws.register_path_route(r"/bad/.*", str(regular_file))
        except ValueError:
            pass

        assert pws.registeredroutes == routes_before, (
            "registeredroutes must be identical after a rejected root-as-file registration"
        )

    def test_valid_directory_is_still_accepted(self, mock_platformweb_service, tmp_path):
        """A valid directory root must succeed and insert exactly one route.

        Regression guard: the new checks must not break legitimate callers."""
        pws = mock_platformweb_service
        valid_dir = tmp_path / "valid_root"
        valid_dir.mkdir()
        before = len(pws.registeredroutes)

        pws.register_path_route(r"/valid/.*", str(valid_dir))

        path_routes = [r for r in pws.registeredroutes if r[1] == 'path']
        assert len(pws.registeredroutes) == before + 1, (
            "A valid directory registration must insert exactly one route"
        )
        assert any(str(valid_dir.resolve()) == r[2] for r in path_routes), (
            "The registered root must be the canonicalized valid directory"
        )


# ---------------------------------------------------------------------------
# Group 4b: Two-sided capability gate enforcement
# ---------------------------------------------------------------------------

class TestCapabilityGateEnforcement:
    """The RPC.allow decorator on register_path_route must be enforced at
    call time, not just annotated.

    Strategy: drive _add_auth_check directly from the RPC subsystem module.
    This tests the enforcement function that wraps the exported method without
    requiring a full live VIP bus. We confirm:
      - A caller WITHOUT the capability is rejected (exception raised, no
        route inserted).
      - A caller WITH the capability succeeds (route inserted).

    This is honest about what is exercised: we drive the same
    checked_method closure that the VIP RPC dispatcher calls, using a
    mocked RPC subsystem with controllable get_capabilities responses.
    """

    def _make_rpc_subsystem_mock(self, capabilities_for_user):
        """Build a minimal mock that _add_auth_check can use.

        _add_auth_check is a method on the RPC subsystem class; it closes
        over self._owner.vip.auth.get_capabilities and
        self.context.vip_message.user. We replicate that structure here.
        """
        from volttron.client.vip.agent import RPC as RPCSubsystem

        owner_mock = MagicMock()
        owner_mock.vip.auth.get_capabilities.return_value = capabilities_for_user

        context_mock = MagicMock()
        context_mock.vip_message.user = "test-user"
        # message_bus affects user-name stripping; use 'zmq' to skip it
        context_mock.vip_message.peer = "test-agent"

        rpc_sub = RPCSubsystem.__new__(RPCSubsystem)
        rpc_sub._owner = owner_mock
        rpc_sub.context = context_mock
        rpc_sub._message_bus = "zmq"

        return rpc_sub

    def test_uncapable_caller_is_rejected_no_route_inserted(
        self, mock_platformweb_service, tmp_path
    ):
        """A caller without 'register_path_route' capability must be denied.

        The checked_method closure (returned by _add_auth_check) must raise
        and the route must NOT be inserted into registeredroutes."""
        from volttron.utils import jsonrpc as _jsonrpc

        pws = mock_platformweb_service
        valid_dir = tmp_path / "cap_test_root_uncap"
        valid_dir.mkdir()
        before = len(pws.registeredroutes)

        rpc_sub = self._make_rpc_subsystem_mock(
            # User has NO capabilities at all.
            capabilities_for_user={}
        )
        required_caps = {"register_path_route"}

        # Bind the unbound PlatformWebService.register_path_route to pws so
        # _add_auth_check can call it as method(*args, **kwargs).
        bound_method = PlatformWebService.register_path_route.__get__(pws, type(pws))
        checked = rpc_sub._add_auth_check(bound_method, required_caps)

        with pytest.raises(Exception) as exc_info:
            checked(r"/uncap/.*", str(valid_dir))

        # Must have raised an UNAUTHORIZED-flavoured exception. jsonrpc
        # exception_from_json returns a RemoteError whose repr is
        # Error(-32001, "..."); str() returns only the message part.
        # We check repr() which includes the numeric error code, OR we check
        # for an 'error_code' attribute if the exception type carries it.
        exc_repr = repr(exc_info.value)
        exc_code = getattr(exc_info.value, "error_code", None) or \
                   getattr(exc_info.value, "code", None)
        assert (
            str(_jsonrpc.UNAUTHORIZED) in exc_repr
            or exc_code == _jsonrpc.UNAUTHORIZED
        ), f"Expected UNAUTHORIZED exception for uncapable caller, got: {exc_info.value!r}"

        # Critical: no route must have been inserted (data-invariants Rule 1).
        assert len(pws.registeredroutes) == before, (
            "An uncapable caller rejection must not insert any route into registeredroutes"
        )

    def test_capable_caller_succeeds_and_route_inserted(
        self, mock_platformweb_service, tmp_path
    ):
        """A caller WITH 'register_path_route' capability must be allowed and
        the route must be inserted."""
        pws = mock_platformweb_service
        valid_dir = tmp_path / "cap_test_root_cap"
        valid_dir.mkdir()
        before = len(pws.registeredroutes)

        rpc_sub = self._make_rpc_subsystem_mock(
            # User has the required capability (no argument restrictions).
            capabilities_for_user={"register_path_route": None}
        )
        required_caps = {"register_path_route"}

        bound_method = PlatformWebService.register_path_route.__get__(pws, type(pws))
        checked = rpc_sub._add_auth_check(bound_method, required_caps)

        checked(r"/cap/.*", str(valid_dir))

        assert len(pws.registeredroutes) == before + 1, (
            "A capable caller must insert exactly one route into registeredroutes"
        )
        path_routes = [r for r in pws.registeredroutes if r[1] == 'path']
        assert any(str(valid_dir.resolve()) == r[2] for r in path_routes), (
            "The inserted route must carry the canonicalized root directory"
        )


# ---------------------------------------------------------------------------
# Group 4c: OSError at serve time returns 403 not 500
# ---------------------------------------------------------------------------

class TestOSErrorAt503:
    """Path.resolve() can raise OSError on a broken symlink or a permission
    error. The serve-time handler must catch it and return 403 (fail-closed),
    not propagate a 500."""

    def test_oserror_in_safe_path_returns_403_not_500(
        self, mock_platformweb_service, web_root
    ):
        """Simulate Path.resolve raising OSError inside _safe_path_within_root
        and assert: 403 status returned, no file bytes in body."""
        pws = mock_platformweb_service
        pws.register_path_route(r"/.*", str(web_root["root"]))

        start_response = MagicMock()

        with patch(
            "volttron.platform.web.platform_web_service.Path.resolve",
            side_effect=OSError("simulated broken symlink"),
        ):
            data = pws.app_routing(
                get_test_web_env("/index.html"), start_response
            )

        body = b"".join(data).decode("utf-8", errors="replace")

        assert "403 Forbidden" in start_response.call_args[0], (
            "OSError during path resolution must yield 403 Forbidden, not 500"
        )
        # The legitimate file bytes must not appear (fail-closed).
        assert "LEGITIMATE CONTENT" not in body, (
            "No file bytes must be served when Path.resolve raises OSError"
        )