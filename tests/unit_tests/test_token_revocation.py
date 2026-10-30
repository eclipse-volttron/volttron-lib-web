"""Tests for web session revocation: ``DELETE /authenticate`` (CERT VU#173170.1, claim 6).

Every token minted at a login carries the same ``sid`` claim. Revoking the session refuses all of them at once - on
renewal, on the service's own claim check that every endpoint and peer agent relies on, and for websockets that were
opened with them - and survives a restart of the web service.
"""

import json
import os
import stat
import time
from unittest.mock import MagicMock

import jwt
import pytest
from pydantic import SecretStr
from ws4py.websocket import WebSocket

from volttron.services.web.authenticate_endpoint import AuthenticateEndpoints
from volttron.services.web.platform_web_service import PlatformWebService
from volttron.services.web.token_revocation import (RevokedSessions, REVOKED_SESSIONS_FILE, SESSION_CLAIM,
                                                    session_id)
from volttron.services.web.user_manager import add_web_user
from volttron.services.web.vui_pubsub import VUIPubsubManager, VUIWebSocket
from volttrontesting.platformwrapper import create_volttron_home, with_os_environ
from web_utils import get_test_web_env

USER = "revoke_user"
PASSWORD = "Pass123"


def _random_key():
    return os.urandom(48).hex()


@pytest.fixture
def server():
    """Yields (endpoints, secret, volttron_home) with one vui/admin user stored in a fresh VOLTTRON_HOME."""
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        add_web_user(USER, PASSWORD, groups=["admin", "vui"])
        secret = _random_key()
        endpoints = AuthenticateEndpoints(web_secret_key=secret)
        try:
            yield endpoints, secret, volttron_home
        finally:
            endpoints._observer.stop()


def _login(endpoints):
    env = get_test_web_env("/authenticate", method="POST")
    response = endpoints.handle_authenticate(env, {"username": USER, "password": PASSWORD})
    assert response.status_code == 200
    return json.loads(response.get_data())


def _renew(endpoints, refresh_token):
    env = get_test_web_env("/authenticate", method="PUT")
    env["HTTP_AUTHORIZATION"] = "BEARER " + refresh_token
    return endpoints.handle_authenticate(env, data={})


def _revoke(endpoints, token=None, **env_extra):
    env = get_test_web_env("/authenticate", method="DELETE", **env_extra)
    if token is not None:
        env["HTTP_AUTHORIZATION"] = "Bearer " + token
    return endpoints.handle_authenticate(env, data=None)


def _claims(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])


def _service_with(endpoints, secret):
    """A PlatformWebService whose get_user_claims runs for real against the endpoints' deny-list."""
    svc = PlatformWebService.__new__(PlatformWebService)
    svc.config = MagicMock()
    svc.config.ssl_cert = None
    svc.config.secret_key = SecretStr(secret)
    svc._revoked_sessions = endpoints.revoked_sessions
    svc._vui_endpoints = None
    return svc


# ---------------------------------------------------------------- session ids

def test_login_tokens_share_one_session_id_and_renewal_inherits_it(server):
    endpoints, secret, _ = server
    tokens = _login(endpoints)
    access, refresh = _claims(tokens["access_token"], secret), _claims(tokens["refresh_token"], secret)
    assert session_id(access) and session_id(access) == session_id(refresh)
    assert access['sub'] == refresh['sub'] == USER    # the user is named independently of the session
    renewed = json.loads(_renew(endpoints, tokens["refresh_token"]).get_data())["access_token"]
    assert session_id(_claims(renewed, secret)) == session_id(access)
    # A second login is a different session.
    assert session_id(_claims(_login(endpoints)["access_token"], secret)) != session_id(access)


def test_token_without_session_id_is_refused_everywhere(server):
    endpoints, secret, _ = server
    now = int(time.time())
    legacy = {"groups": ["admin", "vui"], "iat": now, "nbf": now, "exp": now + 600}
    legacy_access = jwt.encode(dict(legacy, grant_type="access_token"), secret, algorithm="HS256")
    legacy_refresh = jwt.encode(dict(legacy, grant_type="refresh_token"), secret, algorithm="HS256")
    assert _renew(endpoints, legacy_refresh).status_code == 401
    assert _service_with(endpoints, secret).get_user_claims(legacy_access) == {}
    assert _revoke(endpoints, legacy_access).status_code == 401


# ---------------------------------------------------------------- DELETE /authenticate

@pytest.mark.parametrize("presented", ["refresh_token", "access_token"])
def test_revoking_either_token_refuses_the_whole_session(server, presented):
    endpoints, secret, _ = server
    tokens = _login(endpoints)
    svc = _service_with(endpoints, secret)
    assert svc.get_user_claims(tokens["access_token"]).get("groups") == ["admin", "vui"]
    renewed = json.loads(_renew(endpoints, tokens["refresh_token"]).get_data())["access_token"]

    response = _revoke(endpoints, tokens[presented])
    assert response.status_code == 204
    assert response.get_data() == b""

    assert _renew(endpoints, tokens["refresh_token"]).status_code == 401
    assert svc.get_user_claims(tokens["access_token"]) == {}
    assert svc.get_user_claims(renewed) == {}
    # Other sessions are untouched.
    other = _login(endpoints)
    assert svc.get_user_claims(other["access_token"]).get("groups") == ["admin", "vui"]
    assert _renew(endpoints, other["refresh_token"]).status_code == 200


def test_revocation_is_idempotent(server):
    endpoints, _, _ = server
    tokens = _login(endpoints)
    assert _revoke(endpoints, tokens["refresh_token"]).status_code == 204
    assert _revoke(endpoints, tokens["refresh_token"]).status_code == 204
    assert _revoke(endpoints, tokens["access_token"]).status_code == 204
    assert len(endpoints.revoked_sessions) == 1


def test_revocation_requires_a_valid_token_in_the_authorization_header(server):
    endpoints, secret, _ = server
    tokens = _login(endpoints)
    other_key = jwt.encode(_claims(tokens["access_token"], secret), _random_key(), algorithm="HS256")
    expired_claims = dict(_claims(tokens["access_token"], secret), exp=int(time.time()) - 5)
    expired = jwt.encode(expired_claims, secret, algorithm="HS256")

    assert _revoke(endpoints).status_code == 401
    assert _revoke(endpoints, "not.a.token").status_code == 401
    assert _revoke(endpoints, other_key).status_code == 401
    assert _revoke(endpoints, expired).status_code == 401
    # The cookie alone never revokes: a browser attaches it to requests other sites make.
    assert _revoke(endpoints, HTTP_COOKIE="Bearer=" + tokens["access_token"]).status_code == 401
    assert len(endpoints.revoked_sessions) == 0
    assert _renew(endpoints, tokens["refresh_token"]).status_code == 200


def test_revocation_entry_outlives_every_token_of_the_session(server):
    endpoints, secret, _ = server
    tokens = _login(endpoints)
    issued = _claims(tokens["access_token"], secret)["iat"]
    _revoke(endpoints, tokens["access_token"])
    sid = session_id(_claims(tokens["access_token"], secret))
    stored = endpoints.revoked_sessions._expiry[sid]
    assert stored >= issued + (endpoints.refresh_token_timeout + endpoints.access_token_timeout) * 60


def test_on_revoke_hook_runs_and_its_failure_does_not_undo_the_revocation(server):
    endpoints, secret, _ = server
    hook = MagicMock(side_effect=RuntimeError("boom"))
    endpoints._on_revoke = hook
    tokens = _login(endpoints)
    assert _revoke(endpoints, tokens["access_token"]).status_code == 204
    hook.assert_called_once_with(session_id(_claims(tokens["access_token"], secret)))
    assert not endpoints.revoked_sessions.allows(_claims(tokens["access_token"], secret))


# ---------------------------------------------------------------- persistence

def test_revocations_persist_across_restart_with_private_file(server):
    endpoints, secret, volttron_home = server
    tokens = _login(endpoints)
    _revoke(endpoints, tokens["refresh_token"])
    path = os.path.join(volttron_home, REVOKED_SESSIONS_FILE)
    assert endpoints.revoked_sessions.path == path
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    reloaded = RevokedSessions(path)
    assert not reloaded.allows(_claims(tokens["access_token"], secret))
    restarted = AuthenticateEndpoints(web_secret_key=secret, revoked_sessions=reloaded)
    try:
        assert _renew(restarted, tokens["refresh_token"]).status_code == 401
    finally:
        restarted._observer.stop()


def test_expired_entries_are_dropped_on_load_check_and_revoke(tmp_path):
    path = str(tmp_path / "revoked.json")
    revoked = RevokedSessions(path)
    revoked.revoke("gone", time.time() - 1)
    assert len(revoked) == 0 and not os.path.exists(path)
    revoked.revoke("soon", time.time() + 0.2)
    revoked.revoke("later", time.time() + 3600)
    assert revoked.is_revoked("soon") and len(RevokedSessions(path)) == 2
    time.sleep(0.3)
    assert not revoked.is_revoked("soon")
    assert len(RevokedSessions(path)) == 1
    revoked.revoke("other", time.time() + 3600)
    assert set(json.load(open(path))) == {"later", "other"}


@pytest.mark.parametrize("content", ["not json", "[1, 2]", '{"x": "notanumber", "y": true, "": 9e12, "ok": 9e12}'])
def test_damaged_or_odd_revocation_file_is_tolerated(tmp_path, content):
    path = tmp_path / "revoked.json"
    path.write_text(content)
    revoked = RevokedSessions(str(path))
    assert revoked.is_revoked("ok") == ("ok" in content)
    assert not revoked.is_revoked("x") and not revoked.is_revoked("y") and not revoked.is_revoked("")


@pytest.mark.parametrize("claims", [None, [], {}, {SESSION_CLAIM: ""}, {SESSION_CLAIM: 5}, {SESSION_CLAIM: "x" * 65}])
def test_unusable_session_ids_are_not_allowed(tmp_path, claims):
    revoked = RevokedSessions(str(tmp_path / "revoked.json"))
    assert session_id(claims) is None
    assert not revoked.allows(claims)
    with pytest.raises(ValueError):
        revoked.revoke(claims.get(SESSION_CLAIM) if isinstance(claims, dict) else claims, time.time() + 60)


# ---------------------------------------------------------------- websockets

class _FakeSocket(VUIWebSocket):
    # ws4py's ``terminated`` property reads these two flags.
    def __init__(self):
        self.client_terminated = self.server_terminated = False
        self.closed_with = None
        self.environ = {}

    def close(self, code=1000, reason=""):
        self.closed_with = reason
        self.client_terminated = self.server_terminated = True


def _token(secret, sid):
    return jwt.encode({SESSION_CLAIM: sid, "grant_type": "access_token", "groups": ["vui"]}, secret, "HS256")


def _open(manager, sid, topic, sock=None):
    sock = sock or _FakeSocket()
    manager.client_opened(sock, topic, f"token-{sid}", {SESSION_CLAIM: sid, "groups": ["vui"]})
    return sock


def test_close_session_sockets_closes_only_the_revoked_session():
    agent = MagicMock()
    manager = VUIPubsubManager(agent)
    doomed_a, doomed_b = _open(manager, "doomed", "devices/a"), _open(manager, "doomed", "devices/b")
    kept = _open(manager, "kept", "devices/a")

    assert manager.close_session_sockets("doomed") == 2
    assert doomed_a.closed_with == "Session revoked" and doomed_b.terminated
    assert kept.closed_with is None
    # The revoked sockets' subscriptions are released, the kept one's is not.
    unsubscribed = {(c.args[1], c.args[2]) for c in agent.vip.pubsub.unsubscribe.call_args_list}
    assert unsubscribed == {("devices/a", doomed_a.on_topic), ("devices/b", doomed_b.on_topic)}
    assert "doomed" not in manager._sockets and kept in manager._sockets["kept"]
    assert manager.close_session_sockets("doomed") == 0
    assert manager.close_session_sockets("never-seen") == 0


def test_service_closes_websockets_of_a_revoked_session(server):
    endpoints, secret, _ = server
    svc = _service_with(endpoints, secret)
    endpoints._on_revoke = svc._session_revoked
    svc._session_revoked("nobody-listening")  # no VUI endpoints yet: nothing to do, no error
    svc._vui_endpoints = MagicMock()
    manager = svc._vui_endpoints.pubsub_manager = VUIPubsubManager(MagicMock())
    tokens = _login(endpoints)
    sock = _FakeSocket()
    manager.client_opened(sock, "devices/a", tokens["access_token"], _claims(tokens["access_token"], secret))

    assert _revoke(endpoints, tokens["refresh_token"]).status_code == 204
    assert sock.terminated and sock.closed_with == "Session revoked"


def test_pubsub_manager_without_sockets_is_fine(server):
    endpoints, secret, _ = server
    svc = _service_with(endpoints, secret)
    svc._vui_endpoints = MagicMock(spec=[])  # VUIEndpoints built without the pubsub route
    svc._session_revoked("whatever")
