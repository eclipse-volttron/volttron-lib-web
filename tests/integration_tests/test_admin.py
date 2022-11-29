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

import gevent
import pytest


@pytest.fixture(scope="module")
def user_pass():
    yield 'admin', 'admin'


def test_can_authenticate_admin_user(volttron_instance, user_pass):
    instance = volttron_instance

    webadmin = instance.web_admin_api

    user, password = user_pass
    gevent.sleep(1)
    resp = webadmin.authenticate(user, password)
    assert resp.ok
    assert resp.headers.get('Content-Type') == 'application/json'

    resp = webadmin.authenticate('fake', password)
    assert resp.status_code == 401  # unauthorized
    assert resp.headers.get('Content-Type') == 'application/json'


@pytest.mark.skip(reason="Can't test using platformwrapper. Needs to be unit test")
def test_can_create_admin_user(volttron_instance, user_pass):
    instance = volttron_instance
    webadmin = instance.web_admin_api
    user, password = user_pass

    resp = webadmin.create_web_admin(user, password)
    assert resp.ok
    # Allow file operation to run
    gevent.sleep(2)

    resp = webadmin.authenticate(user, password)
    assert resp.ok
    assert resp.headers.get('Content-Type') == 'application/json'

    resp = webadmin.authenticate('fake', password)
    assert resp.status_code == 401  # unauthorized
    assert resp.headers.get('Content-Type') == 'text/html'

