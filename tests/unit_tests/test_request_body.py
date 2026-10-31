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

"""A request body that is not what its content type claims is answered with 400 before any route runs."""

import pytest

from volttron.utils import jsonapi
from web_utils import get_test_web_env, mock_platform_web_service


def _route(svc, body: bytes, content_type='application/json', path='/vui/platforms'):
    env = get_test_web_env(path, input_data=body, method='POST', CONTENT_TYPE=content_type,
                           HTTP_AUTHORIZATION='BEARER foo')
    status = []
    result = svc.app_routing(env, lambda s, h: status.append(s))
    return int(status[0].split()[0]), b''.join(result)


@pytest.mark.parametrize('body', [b'{bad json', b'', b'[1, 2', b'nul'])
def test_malformed_json_body_is_400(mock_platform_web_service, body, caplog):
    status, payload = _route(mock_platform_web_service, body)
    assert status == 400
    assert jsonapi.loads(payload) == {'error': 'Malformed JSON body'}
    assert not body or body.decode('latin-1') not in caplog.text    # the body itself is not logged


def test_non_utf8_body_is_400(mock_platform_web_service):
    status, payload = _route(mock_platform_web_service, b'\xff\xfe{}')
    assert status == 400
    assert jsonapi.loads(payload) == {'error': 'Request body is not UTF-8'}


def test_well_formed_json_body_is_not_refused_by_the_parser(mock_platform_web_service):
    status, payload = _route(mock_platform_web_service, b'{"ok": 1}')
    assert b'Malformed JSON body' not in payload


def test_non_json_content_type_is_not_parsed(mock_platform_web_service):
    status, payload = _route(mock_platform_web_service, b'{bad json', content_type='text/plain')
    assert b'Malformed JSON body' not in payload
