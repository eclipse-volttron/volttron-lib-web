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

import os
import stat
import pytest

from passlib.hash import argon2
from unittest.mock import MagicMock
from urllib.parse import urlencode

from volttron.client.known_identities import PLATFORM_WEB
from volttron.utils import jsonapi
from volttron.utils.jsonrpc import RemoteError

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ

from web_utils import get_test_web_env

from volttron.services.web.admin_endpoints import AdminEndpoints
from volttron.services.web import user_manager

___WEB_USER_FILE_NAME__ = 'web-users.json'


@pytest.fixture()
def volttron_home():
    vhome = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': vhome}):
        yield vhome


def _admin_with_claims(claims=None, error=None):
    """AdminEndpoints whose get_user_claims RPC returns claims or raises error."""
    rpc_caller = MagicMock()
    if error is not None:
        rpc_caller.return_value.get.side_effect = error
    else:
        rpc_caller.return_value.get.return_value = claims
    return AdminEndpoints(rpc_caller=rpc_caller), rpc_caller


# ---------------------------------------------------------------------------
# Unauthenticated paths
# ---------------------------------------------------------------------------

def test_admin_unauthorized(volttron_home):
    adminep = AdminEndpoints()
    # User hasn't logged in so this should be not authorized.
    env = get_test_web_env('/admin/api/boo')
    response = adminep.admin(env, {})
    assert '401 Unauthorized' == response.status
    assert b'Unauthorized User' in response.response[0]


def test_setpassword_without_users_is_unauthorized(volttron_home):
    """First-run credential creation was removed (web users are created with ``vctl web``).

    With no users configured, an unauthenticated POST to /admin/setpassword must be
    rejected and must not create any user.
    """
    webuserpath = os.path.join(volttron_home, ___WEB_USER_FILE_NAME__)
    adminep = AdminEndpoints()

    params = urlencode(dict(username='attacker', password1='pwn', password2='pwn'))
    env = get_test_web_env("/admin/setpassword", method='POST')
    jinja_mock = env['JINJA2_TEMPLATE_ENV']
    response = adminep.admin(env, params)

    assert 401 == response.status_code
    assert b'Unauthorized User' in response.response[0]
    assert 'Location' not in response.headers
    # No first-run template is rendered and no credential is written.
    assert 0 == jinja_mock.get_template.call_count
    assert not os.path.exists(webuserpath)
    assert user_manager.load_web_users() == {}


@pytest.mark.parametrize("path", ["/admin/", "/admin/login.html"])
def test_admin_login_page(volttron_home, path):
    adminep = AdminEndpoints()
    myenv = get_test_web_env(path=path)
    response = adminep.admin(myenv, {})
    jinja_mock = myenv['JINJA2_TEMPLATE_ENV']
    assert 1 == jinja_mock.get_template.call_count
    assert ('login.html',) == jinja_mock.get_template.call_args[0]
    assert 1 == jinja_mock.get_template.return_value.render.call_count
    assert 'text/html' == response.headers.get('Content-Type')
    assert '200 OK' == response.status


# ---------------------------------------------------------------------------
# Token validation is fail-closed
# ---------------------------------------------------------------------------

def test_admin_page_with_admin_claims(volttron_home):
    adminep, rpc_caller = _admin_with_claims({'groups': ['admin', 'vui'], 'grant_type': 'access_token'})
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Bearer good-token')
    response = adminep.admin(env, {})
    assert '200 OK' == response.status
    assert ('index.html',) == env['JINJA2_TEMPLATE_ENV'].get_template.call_args[0]
    rpc_caller.assert_called_once_with(PLATFORM_WEB, 'get_user_claims', 'good-token')


def test_admin_page_accepts_bearer_cookie(volttron_home):
    adminep, _ = _admin_with_claims({'groups': ['admin']})
    env = get_test_web_env('/admin/index.html', HTTP_COOKIE='Bearer=cookie-token')
    assert '200 OK' == adminep.admin(env, {}).status


def test_admin_page_without_admin_group_is_unauthorized(volttron_home):
    adminep, _ = _admin_with_claims({'groups': ['vui']})
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Bearer vui-only')
    response = adminep.admin(env, {})
    assert '401 Unauthorized' == response.status
    assert 0 == env['JINJA2_TEMPLATE_ENV'].get_template.call_count


@pytest.mark.parametrize("claims", [{}, None, {'grant_type': 'refresh_token'}, {'groups': None}])
def test_admin_page_with_tokens_lacking_groups_is_unauthorized(volttron_home, claims):
    """A refresh token (claims stripped to {}) or a token without groups must not reach any page."""
    adminep, _ = _admin_with_claims(claims)
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Bearer refresh-token')
    response = adminep.admin(env, {})
    assert '401 Unauthorized' == response.status
    assert 0 == env['JINJA2_TEMPLATE_ENV'].get_template.call_count


@pytest.mark.parametrize("exc_type", ["InvalidSignatureError", "DecodeError", "InvalidAlgorithmError", ""])
def test_admin_page_with_invalid_token_is_unauthorized(volttron_home, exc_type):
    """Any token the web service refuses (other than expiry) yields 401, never a page or a 500."""
    error = RemoteError("bad token", exc_type=exc_type, exc_args=[])
    adminep, _ = _admin_with_claims(error=error)
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Bearer tampered')
    response = adminep.admin(env, {})
    assert '401 Unauthorized' == response.status
    assert 0 == env['JINJA2_TEMPLATE_ENV'].get_template.call_count


def test_admin_page_with_expired_token_shows_login(volttron_home):
    error = RemoteError("expired", exc_type="jwt.ExpiredSignatureError", exc_args=[])
    adminep, _ = _admin_with_claims(error=error)
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Bearer expired')
    response = adminep.admin(env, {})
    assert '200 OK' == response.status
    assert ('login.html',) == env['JINJA2_TEMPLATE_ENV'].get_template.call_args[0]


def test_admin_malformed_authorization_header_is_unauthorized(volttron_home):
    adminep, _ = _admin_with_claims({'groups': ['admin']})
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='Basic dXNlcjpwYXNz')
    assert '401 Unauthorized' == adminep.admin(env, {}).status
    env = get_test_web_env('/admin/index.html', HTTP_AUTHORIZATION='garbage')
    assert '401 Unauthorized' == adminep.admin(env, {}).status


def test_admin_unknown_template_is_not_found(volttron_home):
    from jinja2 import TemplateNotFound
    adminep, _ = _admin_with_claims({'groups': ['admin']})
    env = get_test_web_env('/admin/pending_auth_reqs.html', HTTP_AUTHORIZATION='Bearer good-token')
    env['JINJA2_TEMPLATE_ENV'].get_template.side_effect = TemplateNotFound('pending_auth_reqs.html')
    response = adminep.admin(env, {})
    assert '404 Not Found' == response.status


def test_admin_credential_api_removed():
    """The /admin/api credential and CSR handlers depended on RPC methods the auth service does not provide."""
    for name in ('_AdminEndpoints__api_endpoint', '_AdminEndpoints__approve_credential_api',
                 '_AdminEndpoints__pending_csrs_api', 'add_user'):
        assert not hasattr(AdminEndpoints, name)


# ---------------------------------------------------------------------------
# Web users are managed by user_manager (vctl web)
# ---------------------------------------------------------------------------

def test_add_web_user_writes_hashed_password_with_restricted_permissions(volttron_home):
    webuserpath = os.path.join(volttron_home, ___WEB_USER_FILE_NAME__)
    assert not os.path.exists(webuserpath)

    user_manager.add_web_user("test", "passwd", ['admin'])

    assert os.path.exists(webuserpath)
    assert stat.S_IMODE(os.stat(webuserpath).st_mode) == 0o600
    with open(webuserpath) as fp:
        users = jsonapi.load(fp)
    assert list(users) == ["test"]
    assert users["test"]["groups"] == ['admin']
    assert argon2.verify("passwd", users["test"]["hashed_password"])
    assert "passwd" not in open(webuserpath).read()


def test_add_web_user_requires_overwrite_for_existing_user(volttron_home):
    user_manager.add_web_user("test", "passwd", ['admin'])
    original = user_manager.load_web_users()["test"]["hashed_password"]

    with pytest.raises(ValueError, match="The user test is already present and overwrite not set to True"):
        user_manager.add_web_user("test", "passwd", ['admin'])

    user_manager.add_web_user("test", "passwd", ['read_only', 'jr-devs'], overwrite=True)
    users = user_manager.load_web_users()
    assert len(users) == 1
    assert users["test"]["groups"] == ['read_only', 'jr-devs']
    assert users["test"]["hashed_password"] != original


def test_update_delete_list_web_users(volttron_home):
    user_manager.add_web_user("a", "pw-a", ['admin', 'vui'])
    user_manager.add_web_user("b", "pw-b", ['vui'])

    listed = user_manager.list_web_users()
    assert set(listed) == {"a", "b"}
    assert all('hashed_password' not in u for u in listed.values())
    assert user_manager.get_web_user("b") == {'groups': ['vui']}

    user_manager.update_web_user("b", unencrypted_pw="new-pw", groups=['admin'])
    stored = user_manager.load_web_users()["b"]
    assert stored['groups'] == ['admin']
    assert argon2.verify("new-pw", stored['hashed_password'])

    user_manager.delete_web_user("a")
    assert set(user_manager.load_web_users()) == {"b"}
    with pytest.raises(ValueError):
        user_manager.delete_web_user("a")
    with pytest.raises(ValueError):
        user_manager.get_web_user("a")
