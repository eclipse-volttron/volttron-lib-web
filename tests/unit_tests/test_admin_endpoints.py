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
import pytest

from passlib.hash import argon2
from urllib.parse import urlencode

from volttron.utils import jsonapi

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ

from web_utils import get_test_web_env

from volttron.services.web.admin_endpoints import AdminEndpoints

___WEB_USER_FILE_NAME__ = 'web-users.json'


def test_admin_unauthorized():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        myuser = 'testing'
        mypass = 'funky'
        adminep = AdminEndpoints()
        adminep.add_user(myuser, mypass)

        # User hasn't logged in so this should be not authorized.
        env = get_test_web_env('/admin/api/boo')
        response = adminep.admin(env, {})
        assert '401 Unauthorized' == response.status
        assert b'Unauthorized User' in response.response[0]


def test_setpassword_without_users_is_unauthorized():
    """First-run credential creation was removed (web users are created with ``vctl web``).

    With an empty user store, an unauthenticated POST to /admin/setpassword must be
    rejected and must not create any user.
    """
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        webuserpath = os.path.join(volttron_home, ___WEB_USER_FILE_NAME__)
        adminep = AdminEndpoints()
        assert len(adminep._userdict) == 0

        params = urlencode(dict(username='attacker', password1='pwn', password2='pwn'))
        env = get_test_web_env("/admin/setpassword", method='POST')
        jinja_mock = env['JINJA2_TEMPLATE_ENV']
        response = adminep.admin(env, params)

        assert 401 == response.status_code
        assert b'Unauthorized User' in response.response[0]
        assert 'Location' not in response.headers
        # No first-run template is rendered and no credential is written.
        assert 0 == jinja_mock.get_template.call_count
        assert len(adminep._userdict) == 0
        assert not os.path.exists(webuserpath)


def test_admin_root_renders_login_page():
    """/admin/ shows the login page even when no users exist yet."""
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        adminep = AdminEndpoints()
        env = get_test_web_env("/admin/")
        jinja_mock = env['JINJA2_TEMPLATE_ENV']
        response = adminep.admin(env, {})
        assert '200 OK' == response.status
        assert ('login.html',) == jinja_mock.get_template.call_args[0]


def test_admin_login_page():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        username_test = "mytest"
        username_test_passwd = "value-plus"
        adminep = AdminEndpoints()
        adminep.add_user(username_test, username_test_passwd, ['admin'])
        myenv = get_test_web_env(path='login.html')
        response = adminep.admin(myenv, {})
        jinja_mock = myenv['JINJA2_TEMPLATE_ENV']
        assert 1 == jinja_mock.get_template.call_count
        assert ('login.html',) == jinja_mock.get_template.call_args[0]
        assert 1 == jinja_mock.get_template.return_value.render.call_count
        assert 'text/html' == response.headers.get('Content-Type')
        # assert ('Content-Type', 'text/html') in response.headers
        assert '200 OK' == response.status


def test_persistent_users():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        username_test = "mytest"
        username_test_passwd = "value-plus"
        adminep = AdminEndpoints()
        oid = id(adminep)
        adminep.add_user(username_test, username_test_passwd, ['admin'])

        another_ep = AdminEndpoints()
        assert oid != id(another_ep)
        assert len(another_ep._userdict) == 1
        assert username_test == list(another_ep._userdict)[0]


def test_add_user():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        webuserpath = os.path.join(os.environ.get('VOLTTRON_HOME'), ___WEB_USER_FILE_NAME__)
        assert not os.path.exists(webuserpath)

        username_test = "test"
        username_test_passwd = "passwd"
        adminep = AdminEndpoints()
        adminep.add_user(username_test, username_test_passwd, ['admin'])

        # since add_user is async with persistance we use sleep to allow the write
        # gevent.sleep(0.01)
        assert os.path.exists(webuserpath)

        with open(webuserpath) as fp:
            users = jsonapi.load(fp)

        assert len(users) == 1
        assert users.get(username_test) is not None
        user = users.get(username_test)
        objid = id(user)
        assert ['admin'] == user['groups']
        assert user['hashed_password'] is not None
        original_hashed_passwordd = user['hashed_password']

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
        assert original_hashed_passwordd != user['hashed_password']
