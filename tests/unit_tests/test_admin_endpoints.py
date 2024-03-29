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
from volttron.utils.keystore import get_random_key

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ

from web_utils import get_test_web_env

from volttron.services.web.admin_endpoints import AdminEndpoints

___WEB_USER_FILE_NAME__ = 'web-users.json'


def test_admin_unauthorized():
    volttron_home = create_volttron_home()
    config_params = {"web-secret-key": get_random_key(), 'VOLTTRON_HOME': volttron_home}

    with with_os_environ(config_params):
        myuser = 'testing'
        mypass = 'funky'
        adminep = AdminEndpoints()
        adminep.add_user(myuser, mypass)

        # User hasn't logged in so this should be not authorized.
        env = get_test_web_env('/admin/api/boo')
        response = adminep.admin(env, {})
        assert '401 Unauthorized' == response.status
        assert b'Unauthorized User' in response.response[0]


def test_set_platform_password_setup():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        # Note these passwords are not right so we expect to be redirected back to the
        # first.html
        params = urlencode(dict(username='bart', password1='goodwin', password2='wowsa'))
        env = get_test_web_env("/admin/setpassword", method='POST')  # , input_data=input)
        jinja_mock = env['JINJA2_TEMPLATE_ENV']
        adminep = AdminEndpoints()
        response = adminep.admin(env, params)

        assert 'Location' not in response.headers
        assert 200 == response.status_code
        assert 'text/html' == response.headers.get('Content-Type')

        assert 1 == jinja_mock.get_template.call_count
        assert ('first.html',) == jinja_mock.get_template.call_args[0]
        assert 1 == jinja_mock.get_template.return_value.render.call_count
        jinja_mock.reset_mock()

        # Now we have the correct password1 and password2 set we expect to redirected to
        # /admin/login.html
        params = urlencode(dict(username='bart', password1='wowsa', password2='wowsa'))
        env = get_test_web_env("/admin/setpassword", method='POST')  # , input_data=input)

        # expect Location and Content-Type headers to be set
        response = adminep.admin(env, params)
        assert 3 == len(response.headers)
        assert 'Location' in response.headers
        assert '/admin/login.html' == response.headers.get('Location')
        assert 302 == response.status_code

        webuserpath = os.path.join(os.environ.get('VOLTTRON_HOME'), 'web-users.json')
        with open(webuserpath) as wup:
            users = jsonapi.load(wup)
        assert users.get('bart') is not None
        user = users.get('bart')
        assert user['hashed_password'] is not None
        assert argon2.verify("wowsa", user['hashed_password'])


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
