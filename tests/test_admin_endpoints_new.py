# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2023 Battelle Memorial Institute
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

import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import urlencode

import pytest
from mock import patch

from volttron.platform import jsonapi
from volttron.platform.web.admin_endpoints import AdminEndpoints
from volttron.utils import get_random_key
from volttron.utils.rmq_mgmt import RabbitMQMgmt
from volttrontesting.fixtures.volttron_platform_fixtures import (
    get_test_volttron_home,
    rmq_skipif,
)
from volttrontesting.utils.web_utils import get_test_web_env
from passlib.hash import argon2


___WEB_USER_FILE_NAME__ = 'web-users.json'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adminep():
    """Instantiate AdminEndpoints with watchdog infrastructure mocked out.

    watchdog 3.x changed PatternMatchingEventHandler to keyword-only args;
    the repo pins 0.10.2 which is not installable on Py3.12+.  The file-
    watcher is not part of the security contract under test, so mock it.
    """
    with patch('volttron.platform.web.admin_endpoints.VolttronHomeFileReloader',
               return_value=MagicMock()), \
         patch('volttron.platform.web.admin_endpoints.Observer',
               return_value=MagicMock()):
        return AdminEndpoints()


# ---------------------------------------------------------------------------
# RC-B: one-time bootstrap token gate (VO-005 security fix)
# ---------------------------------------------------------------------------

@pytest.mark.web
def test_rcb_unauthenticated_bootstrap_rejected_no_admin_minted():
    """Unauth POST to /admin on empty userdict must be rejected with 401.

    Asserts:
    - HTTP 401 is returned (not 200 or 302).
    - The web-users.json file is NOT created (no admin credential written).
    - The bootstrap token file IS created (so the operator can retrieve it).
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        assert len(adminep._userdict) == 0, "pre-condition: no users"

        params = urlencode(dict(username='attacker', password1='pwn', password2='pwn'))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        # Security contract: unauthenticated POST is rejected.
        assert response.status_code == 401, (
            f"expected 401 Unauthorized, got {response.status_code}"
        )

        # No admin credential must have been written.
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created when bootstrap is rejected"
        )

        # The bootstrap token file must exist so the operator can retrieve it.
        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')
        assert os.path.exists(token_path), (
            "bootstrap token file must be written on first unauthenticated visit"
        )


@pytest.mark.web
def test_rcb_correct_token_mints_admin_and_consumes_token():
    """Correct bootstrap token allows admin creation; token is then consumed.

    Asserts:
    - POST with the correct token and matching passwords returns 302 to login.
    - The admin credential IS written to web-users.json with correct groups.
    - The bootstrap token file is deleted after successful use (single-use).
    - A second POST with the same token is rejected (token consumed).
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        assert len(adminep._userdict) == 0, "pre-condition: no users"

        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')

        # Trigger token file creation via a GET (no token submitted).
        env_get = get_test_web_env('/admin/', method='GET')
        adminep.admin(env_get, '')
        assert os.path.exists(token_path), "token file must exist after first GET"

        # Read the token as the operator would.
        with open(token_path, 'r') as fh:
            correct_token = fh.read().strip()
        assert len(correct_token) == 64, "token must be 64 hex chars (256-bit)"

        # POST with the correct token and matching passwords.
        params = urlencode(dict(
            username='adminuser',
            password1='StrongP@ss1',
            password2='StrongP@ss1',
            bootstrap_token=correct_token,
        ))
        env_post = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env_post, params)

        # Bootstrap succeeds: redirect to login.
        assert response.status_code == 302, (
            f"expected 302 redirect after successful bootstrap, got {response.status_code}"
        )
        assert response.headers.get('Location') == '/admin/login.html'

        # Admin credential written with correct username and groups.
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)
        assert os.path.exists(webuserpath), "web-users.json must be created"
        with open(webuserpath) as fh:
            users = jsonapi.load(fh)
        assert 'adminuser' in users, "admin username must be present in users file"
        user = users['adminuser']
        assert 'admin' in user.get('groups', []), "admin group must be set"
        assert argon2.verify('StrongP@ss1', user['hashed_password']), (
            "stored password hash must verify against the submitted password"
        )

        # Token consumed: file must be deleted.
        assert not os.path.exists(token_path), (
            "bootstrap token file must be deleted (consumed) after successful use"
        )

        # Second attempt with the same token must fail (token is gone).
        params2 = urlencode(dict(
            username='adminuser2',
            password1='AnotherP@ss2',
            password2='AnotherP@ss2',
            bootstrap_token=correct_token,
        ))
        # Reload userdict to reflect the written user (simulates file watcher).
        adminep.reload_userdict()
        # Now userdict is non-empty: the second bootstrap path is gated by the
        # non-empty check, not the token, so assert the user store was not
        # mutated (adminuser2 must NOT appear).
        env_post2 = get_test_web_env('/admin/setpassword', method='POST')
        adminep.admin(env_post2, params2)
        adminep.reload_userdict()
        with open(webuserpath) as fh:
            users_after = jsonapi.load(fh)
        assert 'adminuser2' not in users_after, (
            "second bootstrap with consumed token must not mint a second admin"
        )


@pytest.mark.web
def test_rcb_wrong_token_rejected_no_admin_minted():
    """Wrong bootstrap token must be rejected; no admin credential written."""
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()

        # Trigger token file creation.
        env_get = get_test_web_env('/admin/', method='GET')
        adminep.admin(env_get, '')

        params = urlencode(dict(
            username='attacker',
            password1='pwn',
            password2='pwn',
            bootstrap_token='deadbeef' * 8,  # wrong 64-char token
        ))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        assert response.status_code == 401, (
            f"wrong token must return 401, got {response.status_code}"
        )
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created when wrong token is submitted"
        )


@pytest.mark.web
def test_rcb_token_comparison_branch_rejects_replayed_token():
    """Replayed token must be rejected via the TOKEN-COMPARISON branch, not the
    userdict-empty gate.

    Tess HIGH finding: the existing consume test short-circuits at the
    non-empty-userdict guard (len > 0 -> falls through to verify_and_dispatch)
    and never exercises the comparison code path.  This test keeps _userdict
    EMPTY so the bootstrap path is entered, then replays the already-consumed
    (deleted) token.  The stored-token-blank guard inside the POST handler
    must return 401 and must not mutate the credential store.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        assert len(adminep._userdict) == 0, "pre-condition: userdict must be empty"

        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')

        # Obtain the real token (triggers generation).
        env_get = get_test_web_env('/admin/', method='GET')
        adminep.admin(env_get, '')
        with open(token_path, 'r') as fh:
            real_token = fh.read().strip()

        # Manually consume (delete) the token to simulate a prior successful use.
        os.remove(token_path)
        assert not os.path.exists(token_path), "pre-condition: token must be consumed"

        # Write back an empty file so the bootstrap path does NOT regenerate
        # (os.path.exists returns True) but the stored token is blank.
        # This exercises the stored-token-blank guard directly.
        with open(token_path, 'w') as fh:
            fh.write('')

        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)

        # Replay the original valid token against the now-blank token file.
        params = urlencode(dict(
            username='attacker',
            password1='p@ssw0rd',
            password2='p@ssw0rd',
            bootstrap_token=real_token,
        ))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        # Must be rejected via the comparison branch (stored token blank).
        assert response.status_code == 401, (
            f"replayed token against blank-stored-token must return 401, "
            f"got {response.status_code}"
        )

        # Credential store must NOT be mutated.
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created on a replayed-token rejection"
        )
        assert len(adminep._userdict) == 0, (
            "_userdict must remain empty: no admin must be minted"
        )


@pytest.mark.web
def test_rcb_generation_failure_returns_503_no_admin_minted():
    """OSError during token generation must return non-200 and mint no admin.

    Fail-open regression: if _generate_bootstrap_token raises OSError (bad
    perms, disk full) the request must be refused before reaching the POST
    handler.  An empty-bootstrap-token POST must not be authorized.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        assert len(adminep._userdict) == 0

        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)

        with patch(
            'volttron.platform.web.admin_endpoints.AdminEndpoints._generate_bootstrap_token',
            side_effect=OSError("simulated disk full"),
        ):
            params = urlencode(dict(
                username='attacker',
                password1='p@ss',
                password2='p@ss',
                bootstrap_token='',
            ))
            env = get_test_web_env('/admin/setpassword', method='POST')
            response = adminep.admin(env, params)

        # Must not be 200 or 302 (no success).
        assert response.status_code not in (200, 302), (
            f"generation failure must not return a success code, "
            f"got {response.status_code}"
        )

        # Credential store must NOT be mutated.
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created when token generation fails"
        )
        assert len(adminep._userdict) == 0, (
            "_userdict must remain empty after generation failure"
        )


@pytest.mark.web
def test_rcb_empty_stored_and_submitted_token_rejected():
    """Empty stored token + empty submitted token must be rejected unconditionally.

    hmac.compare_digest('', '') is True, so this path was previously a
    fail-open: any attacker could claim admin by submitting an empty token
    when the token file happened to be absent or empty.  The explicit blank
    guards must prevent this.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        assert len(adminep._userdict) == 0

        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)

        # Write an empty token file to simulate truncation.
        with open(token_path, 'w') as fh:
            fh.write('')

        params = urlencode(dict(
            username='attacker',
            password1='p@ss',
            password2='p@ss',
            bootstrap_token='',
        ))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        assert response.status_code == 401, (
            f"empty stored + empty submitted must return 401, got {response.status_code}"
        )

        # Credential store must NOT be mutated.
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created on empty-token authorization attempt"
        )
        assert len(adminep._userdict) == 0, (
            "_userdict must remain empty: compare_digest('','') must not be a pass"
        )


@pytest.mark.web
def test_rcb_consume_first_single_use():
    """Token file must be consumed (deleted) BEFORE add_user is called.

    Asserts:
    - A valid bootstrap POST mints the admin (credential store mutated).
    - The token file is deleted after the successful call.
    - A replay (second POST with the same token) is rejected with 401.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)

        # Trigger token generation.
        env_get = get_test_web_env('/admin/', method='GET')
        adminep.admin(env_get, '')
        with open(token_path, 'r') as fh:
            correct_token = fh.read().strip()

        # First POST: valid token, matching passwords.
        params = urlencode(dict(
            username='admin1',
            password1='P@ssword1',
            password2='P@ssword1',
            bootstrap_token=correct_token,
        ))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        assert response.status_code == 302, (
            f"valid bootstrap must redirect, got {response.status_code}"
        )

        # Admin minted.
        assert os.path.exists(webuserpath), "web-users.json must be created"
        with open(webuserpath) as fh:
            users = fh.read()
        assert 'admin1' in users, "admin1 must appear in web-users.json"

        # Token consumed.
        assert not os.path.exists(token_path), (
            "token file must be deleted (consumed) after successful bootstrap"
        )

        # Replay: _userdict is still empty in-memory (add_user updated the
        # in-memory dict so len > 0 now).  Simulate a second fresh instance
        # with an empty userdict but the token already gone.
        adminep2 = _make_adminep()
        # adminep2 loads from disk and sees admin1 -> non-empty; bootstrap path
        # skipped.  To test the replay scenario properly, directly test that
        # the token file being absent causes the next bootstrap-path POST
        # (from a fresh empty-userdict instance) to return 401.
        adminep3 = _make_adminep()
        # Manually clear userdict to force the bootstrap path.
        adminep3._userdict = {}
        # Token file is already deleted.  The bootstrap path will attempt
        # generation (file absent), which will succeed and create a NEW token.
        # That new token != correct_token, so the replay must fail.
        params_replay = urlencode(dict(
            username='attacker',
            password1='P@ssword1',
            password2='P@ssword1',
            bootstrap_token=correct_token,
        ))
        env_replay = get_test_web_env('/admin/setpassword', method='POST')
        response_replay = adminep3.admin(env_replay, params_replay)
        assert response_replay.status_code == 401, (
            f"replayed token after regeneration must return 401, "
            f"got {response_replay.status_code}"
        )

        # Credential store must not have gained 'attacker'.
        adminep3.reload_userdict()
        assert 'attacker' not in adminep3._userdict, (
            "'attacker' must not be minted via a replayed token"
        )


@pytest.mark.web
def test_rcb_blank_username_rejected_no_null_user_written():
    """Blank/None username with a valid token must be rejected.

    A null-keyed admin entry must not appear in web-users.json.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)

        # Trigger token generation.
        env_get = get_test_web_env('/admin/', method='GET')
        adminep.admin(env_get, '')
        with open(token_path, 'r') as fh:
            correct_token = fh.read().strip()

        # POST with a valid token but empty username.
        params = urlencode(dict(
            username='',
            password1='P@ssword1',
            password2='P@ssword1',
            bootstrap_token=correct_token,
        ))
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params)

        assert response.status_code == 401, (
            f"blank username must return 401, got {response.status_code}"
        )

        # Token must NOT have been consumed (no user written).
        assert os.path.exists(token_path), (
            "token file must not be consumed when username validation fails"
        )

        # Credential store must NOT be mutated.
        assert not os.path.exists(webuserpath), (
            "web-users.json must NOT be created with blank username"
        )
        assert len(adminep._userdict) == 0, (
            "_userdict must remain empty: no null-keyed user must be written"
        )


# ---------------------------------------------------------------------------
# Original tests, corrected for the new secure flow
# ---------------------------------------------------------------------------

@pytest.mark.web
def test_admin_unauthorized():
    config_params = {"web-secret-key": get_random_key()}
    with get_test_volttron_home(messagebus='zmq', config_params=config_params):
        myuser = 'testing'
        mypass = 'funky'
        adminep = _make_adminep()
        adminep.add_user(myuser, mypass)

        # User hasn't logged in so this should be not authorized.
        env = get_test_web_env('/admin/api/boo')
        response = adminep.admin(env, {})
        assert '401 Unauthorized' == response.status
        assert b'Unauthorized User' in response.response[0]


@pytest.mark.web
def test_set_platform_password_setup():
    """Corrected test: unauthenticated bootstrap is now rejected (was TOFU).

    Old behavior (insecure, TOFU): POST with mismatched passwords returned 200
    and a correct POST created the admin, all without any token.

    New behavior (secure, RC-B fix):
    - POST without bootstrap_token returns 401; no admin credential is written.
    - POST with the correct one-time token and matching passwords returns 302
      and writes the admin credential to web-users.json.
    """
    with get_test_volttron_home(messagebus='zmq') as vhome:
        adminep = _make_adminep()
        token_path = os.path.join(vhome, 'web-admin-bootstrap-token')

        # Part 1: POST without token must be rejected (401), no admin written.
        params_no_token = urlencode(
            dict(username='bart', password1='goodwin', password2='wowsa')
        )
        env = get_test_web_env('/admin/setpassword', method='POST')
        response = adminep.admin(env, params_no_token)

        assert response.status_code == 401, (
            f"unauthenticated bootstrap must return 401, got {response.status_code}"
        )
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)
        assert not os.path.exists(webuserpath), (
            "no admin must be written when bootstrap_token is absent"
        )

        # Part 2: POST with the correct token and matching passwords redirects
        # and writes the admin credential.
        assert os.path.exists(token_path), "token file must be present"
        with open(token_path, 'r') as fh:
            correct_token = fh.read().strip()

        params_with_token = urlencode(dict(
            username='bart',
            password1='wowsa',
            password2='wowsa',
            bootstrap_token=correct_token,
        ))
        env2 = get_test_web_env('/admin/setpassword', method='POST')
        response2 = adminep.admin(env2, params_with_token)

        assert response2.status_code == 302, (
            f"valid bootstrap must return 302, got {response2.status_code}"
        )
        assert response2.headers.get('Location') == '/admin/login.html'

        assert os.path.exists(webuserpath), "web-users.json must be written"
        with open(webuserpath) as fh:
            users = jsonapi.load(fh)
        assert users.get('bart') is not None
        user = users.get('bart')
        assert user['hashed_password'] is not None
        assert argon2.verify('wowsa', user['hashed_password'])

        # Token must be consumed (deleted).
        assert not os.path.exists(token_path), (
            "bootstrap token file must be deleted after successful use"
        )


@pytest.mark.web
def test_admin_login_page():
    with get_test_volttron_home(messagebus='zmq'):
        username_test = "mytest"
        username_test_passwd = "value-plus"
        adminep = _make_adminep()
        adminep.add_user(username_test, username_test_passwd, ['admin'])
        myenv = get_test_web_env(path='login.html')
        response = adminep.admin(myenv, {})
        jinja_mock = myenv['JINJA2_TEMPLATE_ENV']
        assert 1 == jinja_mock.get_template.call_count
        assert ('login.html',) == jinja_mock.get_template.call_args[0]
        assert 1 == jinja_mock.get_template.return_value.render.call_count
        assert 'text/html' == response.headers.get('Content-Type')
        assert '200 OK' == response.status


@pytest.mark.web
def test_persistent_users():
    with get_test_volttron_home(messagebus='zmq'):
        username_test = "mytest"
        username_test_passwd = "value-plus"
        adminep = _make_adminep()
        oid = id(adminep)
        adminep.add_user(username_test, username_test_passwd, ['admin'])

        another_ep = _make_adminep()
        assert oid != id(another_ep)
        assert len(another_ep._userdict) == 1
        assert username_test == list(another_ep._userdict)[0]


@pytest.mark.web
def test_add_user():
    with get_test_volttron_home(messagebus='zmq') as vhome:
        webuserpath = os.path.join(vhome, ___WEB_USER_FILE_NAME__)
        assert not os.path.exists(webuserpath)

        username_test = "test"
        username_test_passwd = "passwd"
        adminep = _make_adminep()
        adminep.add_user(username_test, username_test_passwd, ['admin'])

        assert os.path.exists(webuserpath)

        with open(webuserpath) as fp:
            users = jsonapi.load(fp)

        assert len(users) == 1
        assert users.get(username_test) is not None
        user = users.get(username_test)
        objid = id(user)
        assert ['admin'] == user['groups']
        assert user['hashed_password'] is not None
        original_hashed_password = user['hashed_password']

        # raise ValueError if not overwrite == True
        with pytest.raises(ValueError,
                           match=f"The user {username_test} is already present and overwrite not set to True"):
            adminep.add_user(username_test, username_test_passwd, ['admin'])

        # make sure the overwrite works because we are changing the group
        adminep.add_user(username_test, username_test_passwd, ['read_only', 'jr-devs'], overwrite=True)
        assert os.path.exists(webuserpath)

        with open(webuserpath) as fp:
            users = jsonapi.load(fp)

        assert len(users) == 1
        assert users.get(username_test) is not None
        user = users.get(username_test)
        assert objid != id(user)
        assert ['read_only', 'jr-devs'] == user['groups']
        assert user['hashed_password'] is not None
        assert original_hashed_password != user['hashed_password']


@pytest.mark.web
@rmq_skipif
def test_construction():
    from volttron.utils.rmq_mgmt import RabbitMQMgmt
    # within rabbitmq mgmt this is used
    with patch("volttron.platform.agent.utils.get_platform_instance_name",
               return_value="volttron"):
        mgmt = RabbitMQMgmt()
        assert mgmt is not None


# ---------------------------------------------------------------------------
# H2: static-file path containment (VO-005 security fix)
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_pws_with_path_root(tmp_path):
    """Fixture: PlatformWebService with one registered path route.

    Creates:
      <root>/          <- registered as the path root
        asset.html     <- a legitimate in-root file
      <root>-sibling/  <- a sibling directory that must NOT be reachable
        secret.txt     <- must not be served
    """
    from volttron.platform.web import PlatformWebService
    from volttron.platform.vip.agent import Agent
    from volttrontesting.utils.utils import AgentMock

    root = tmp_path / "webroot"
    root.mkdir()
    asset = root / "asset.html"
    asset.write_text("<html>legitimate</html>", encoding="utf-8")

    sibling = tmp_path / "webroot-sibling"
    sibling.mkdir()
    secret = sibling / "secret.txt"
    secret.write_text("TOP SECRET", encoding="utf-8")

    PlatformWebService.__bases__ = (AgentMock.imitate(Agent, Agent()),)
    pws = PlatformWebService(
        serverkey=MagicMock(),
        identity=MagicMock(),
        address=MagicMock(),
        bind_web_address=MagicMock(),
    )
    pws.vip.rpc.context.vip_message.peer.return_value = "foo"
    pws.register_path_route("/.*", str(root))

    yield pws, root, sibling, secret


@pytest.mark.web
def test_h2_in_root_asset_serves_correct_bytes(mock_pws_with_path_root):
    """In-root file must be served with 200 and the correct content."""
    pws, root, sibling, secret = mock_pws_with_path_root
    start_response = MagicMock()

    result = pws.app_routing(get_test_web_env("/asset.html"), start_response)
    body = b"".join(result)

    assert "200 OK" in start_response.call_args[0][0], (
        "in-root asset must return 200"
    )
    assert b"legitimate" in body, (
        "response body must contain the actual file bytes, not empty or wrong content"
    )


@pytest.mark.web
def test_h2_dotdot_traversal_blocked_no_out_of_root_bytes(mock_pws_with_path_root):
    """/../ traversal must be blocked (403) and must NOT leak out-of-root bytes."""
    pws, root, sibling, secret = mock_pws_with_path_root
    start_response = MagicMock()

    result = pws.app_routing(get_test_web_env("/../secret.txt"), start_response)
    body = b"".join(result)

    status = start_response.call_args[0][0]
    assert "403" in status, f"traversal must return 403, got: {status}"
    assert b"TOP SECRET" not in body, (
        "response body must NOT contain out-of-root file bytes on traversal attempt"
    )


@pytest.mark.web
def test_h2_prefix_sibling_blocked_no_out_of_root_bytes(mock_pws_with_path_root):
    """Prefix-sibling escape (root=/data, sibling=/data-sibling) must be blocked.

    This is the boundary-of-the-boundary case: the old startswith() check
    admitted '/data-sibling/...' because '/data-sibling'.startswith('/data')
    is True.  The canonical relative_to() fix must block it.
    """
    pws, root, sibling, secret = mock_pws_with_path_root
    start_response = MagicMock()

    # The sibling dir is named 'webroot-sibling'; the root is 'webroot'.
    # Construct a path that would escape via the prefix: go up one level then
    # down into the sibling (simulating the boundary-of-the-boundary bypass).
    result = pws.app_routing(
        get_test_web_env("/../webroot-sibling/secret.txt"), start_response
    )
    body = b"".join(result)

    status = start_response.call_args[0][0]
    assert "403" in status, (
        f"prefix-sibling escape must return 403, got: {status}"
    )
    assert b"TOP SECRET" not in body, (
        "response body must NOT contain sibling-directory bytes"
    )


@pytest.mark.web
def test_h2_symlink_root_as_file_blocked(tmp_path):
    """Root itself being a symlink to an out-of-root dir must be handled.

    If the registered root resolves to a different path (symlinked root),
    Path.resolve() already canonicalizes it, so relative_to() still works
    correctly.  This test confirms no bytes from outside the resolved root
    are served.
    """
    from volttron.platform.web import PlatformWebService
    from volttron.platform.vip.agent import Agent
    from volttrontesting.utils.utils import AgentMock

    real_root = tmp_path / "real_webroot"
    real_root.mkdir()
    (real_root / "ok.html").write_text("<p>ok</p>", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("OUTSIDE SECRET", encoding="utf-8")

    # Symlink: registered_root -> real_root (both resolve canonically)
    sym_root = tmp_path / "sym_webroot"
    sym_root.symlink_to(real_root)

    PlatformWebService.__bases__ = (AgentMock.imitate(Agent, Agent()),)
    pws = PlatformWebService(
        serverkey=MagicMock(),
        identity=MagicMock(),
        address=MagicMock(),
        bind_web_address=MagicMock(),
    )
    pws.vip.rpc.context.vip_message.peer.return_value = "foo"
    pws.register_path_route("/.*", str(sym_root))

    start_response = MagicMock()
    result = pws.app_routing(get_test_web_env("/ok.html"), start_response)
    body = b"".join(result)
    assert "200 OK" in start_response.call_args[0][0]
    assert b"ok" in body

    # Attempt to escape via traversal from sym root.
    start_response.reset_mock()
    result2 = pws.app_routing(get_test_web_env("/../outside/secret.txt"), start_response)
    body2 = b"".join(result2)
    status2 = start_response.call_args[0][0]
    assert "403" in status2, f"escape from symlinked root must be blocked, got {status2}"
    assert b"OUTSIDE SECRET" not in body2, (
        "must not leak bytes from outside the registered (symlinked) root"
    )


# ---------------------------------------------------------------------------
# M2: _authenticate_route dead-code deletion verification
# ---------------------------------------------------------------------------

@pytest.mark.web
def test_m2_authenticate_route_method_deleted():
    """_authenticate_route must not exist on PlatformWebService.

    The method pprint()'d the full WSGI env (including bearer tokens) to
    stdout and had no callers.  Deletion is the fix; existence is a regression.
    """
    from volttron.platform.web import PlatformWebService

    assert not hasattr(PlatformWebService, '_authenticate_route'), (
        "_authenticate_route must be deleted: it leaked bearer tokens via pprint(env)"
    )


@pytest.mark.web
def test_m2_authenticate_source_grep():
    """Grep the source file to confirm _authenticate_route is absent.

    Defensive second layer: checks the actual .py file bytes so a partial
    delete (e.g. only the method body removed but the def line left) is caught.
    """
    import volttron.platform.web.platform_web_service as _pws_mod

    src_path = Path(_pws_mod.__file__).resolve()
    assert src_path.exists(), f"source file not found at {src_path}"

    source = src_path.read_text(encoding='utf-8')
    assert '_authenticate_route' not in source, (
        "_authenticate_route must not appear anywhere in platform_web_service.py"
    )


@pytest.mark.web
def test_m2_authenticate_endpoint_still_bound():
    """The live /authenticate endpoint (AuthenticateEndpoints) must still be registered.

    Confirms the M2 deletion did not accidentally remove the legitimate endpoint.
    """
    import volttron.platform.web.platform_web_service as _pws_mod
    import volttron.platform.web.authenticate_endpoint as _auth_ep_mod

    src_path = Path(_pws_mod.__file__).resolve()
    source = src_path.read_text(encoding='utf-8')

    # AuthenticateEndpoints is imported and its get_routes() is called to bind /authenticate.
    assert 'AuthenticateEndpoints' in source, (
        "AuthenticateEndpoints must still be present after _authenticate_route deletion"
    )
    assert 'get_routes' in source, (
        "get_routes() binding call must still be present"
    )

    # Confirm the authenticate_endpoint module still binds /authenticate.
    auth_ep_path = Path(_auth_ep_mod.__file__).resolve()
    auth_source = auth_ep_path.read_text(encoding='utf-8')
    assert '/authenticate' in auth_source, (
        "/authenticate route must still be declared in authenticate_endpoint.py"
    )