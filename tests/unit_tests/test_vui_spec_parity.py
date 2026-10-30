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

"""Every path in the API specification is answered by a registered route, implemented or 501, never a plain 404."""

import json
import re
from pathlib import Path

import pytest
import yaml

from volttron.services.web.vui_endpoints import VUIEndpoints
from web_utils import get_test_web_env, mock_platform_web_service

SPEC = Path(__file__).resolve().parents[2] / 'src' / 'volttron' / 'services' / 'web' / 'static' / 'specs' / 'vui.specs.yml'


def _spec_paths():
    # /authenticate is served by the web service itself, not by the VUI router.
    return sorted(p for p in yaml.safe_load(SPEC.read_text())['paths'] if p.startswith('/vui'))


def _concrete(spec_path):
    """Replace every {parameter} with a sample segment so the path can be matched against the route patterns."""
    return re.sub(r'\{[^}]+\}', 'sample', spec_path)


@pytest.mark.parametrize('spec_path', _spec_paths())
def test_every_spec_path_has_a_route(mock_platform_web_service, spec_path):
    routes = VUIEndpoints(mock_platform_web_service).get_routes()
    assert any(pattern.match(_concrete(spec_path)) for pattern, _, _ in routes), spec_path


@pytest.mark.parametrize('pattern', VUIEndpoints.UNIMPLEMENTED_SPEC_ROUTES)
def test_unimplemented_spec_routes_answer_501_to_an_authorized_user(mock_platform_web_service, pattern):
    vui = VUIEndpoints(mock_platform_web_service)
    path = pattern.strip('^$').replace('/?', '').replace('[^/]+', 'sample').replace('.+', 'sample')
    assert re.compile(pattern).match(path), path
    response = vui.handle_not_implemented(get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo'), {})
    assert response.status_code == 501
    assert 'not implemented' in json.loads(response.response[0])['error']


def test_unimplemented_spec_routes_still_require_a_token(mock_platform_web_service):
    vui = VUIEndpoints(mock_platform_web_service)
    response = vui.handle_not_implemented(get_test_web_env('/vui/keypair', method='GET'), {})
    assert response.status_code == 401


def test_unknown_paths_match_no_route(mock_platform_web_service):
    routes = VUIEndpoints(mock_platform_web_service).get_routes()
    for path in ('/vui/nonsense', '/vui/platforms/p/nonsense', '/vui/keypairs'):
        assert not any(pattern.match(path) for pattern, _, _ in routes), path
