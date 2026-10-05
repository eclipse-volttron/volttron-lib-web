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

"""Authorization contract of the VUI REST API: every route validates the bearer token and the 'vui' group,
including the pubsub route and the websocket it opens. The RPC proxy allow-list is covered by test_vui_security.py
on the security_fixes branch."""
import json
import pytest

from unittest.mock import MagicMock

from volttron.services.web.vui_endpoints import VUIEndpoints, endpoint
from volttron.services.web.vui_pubsub import VUIWebSocket

from web_utils import get_test_web_env, mock_platform_web_service


def _reject(_bearer):
    raise Exception("invalid token")


@pytest.fixture()
def vui(mock_platform_web_service):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.pubsub_manager = MagicMock()
    vui_endpoints.pubsub_manager.publish.return_value = {'number_of_subscribers': 1}
    vui_endpoints._rpc = MagicMock(return_value={'methods': ['a']})
    return vui_endpoints


PUBSUB = '/vui/platforms/my_instance_name/pubsub/devices/campus/building/point'


class TestPubsubRouteRequiresAuthorization:
    def test_publish_without_token_is_unauthorized(self, vui):
        env = get_test_web_env(PUBSUB, method='PUT')
        response = vui.handle_platforms_pubsub(env, MagicMock(), {'message': 1})
        assert response.status_code == 401
        vui.pubsub_manager.publish.assert_not_called()

    def test_publish_with_invalid_token_is_unauthorized(self, vui):
        vui._agent.get_user_claims = _reject
        env = get_test_web_env(PUBSUB, method='PUT', HTTP_AUTHORIZATION='Bearer forged')
        response = vui.handle_platforms_pubsub(env, MagicMock(), {'message': 1})
        assert response.status_code == 401
        vui.pubsub_manager.publish.assert_not_called()

    @pytest.mark.parametrize("claims", [{}, {'groups': []}, {'groups': ['admin']}, {'groups': None}])
    def test_publish_without_vui_group_is_forbidden(self, vui, claims):
        vui._agent.get_user_claims = lambda bearer: claims
        env = get_test_web_env(PUBSUB, method='PUT', HTTP_AUTHORIZATION='Bearer refresh-or-admin-only')
        response = vui.handle_platforms_pubsub(env, MagicMock(), {'message': 1})
        assert response.status_code == 403
        vui.pubsub_manager.publish.assert_not_called()

    def test_subscribe_without_token_is_unauthorized(self, vui):
        env = get_test_web_env(PUBSUB, method='GET')
        response = vui.handle_platforms_pubsub(env, MagicMock(), {})
        assert response.status_code == 401
        vui.pubsub_manager.open_subscription_socket.assert_not_called()

    def test_authorized_publish_is_forwarded(self, vui):
        env = get_test_web_env(PUBSUB, method='PUT', HTTP_AUTHORIZATION='Bearer good')
        response = vui.handle_platforms_pubsub(env, MagicMock(), {'message': 42, 'headers': {'h': 1}})
        assert response.status_code == 200
        vui.pubsub_manager.publish.assert_called_once_with('devices/campus/building/point', {'h': 1}, 42)

    def test_handler_arity_contract_for_app_routing(self, vui):
        """app_routing calls callables with (env, start_response, data) first and retries with (env, data) on
        TypeError. Wrapped handlers must raise TypeError for the wrong arity before touching the token."""
        vui._agent.get_user_claims = MagicMock(return_value={'groups': ['vui']})
        env = get_test_web_env(PUBSUB, method='PUT', HTTP_AUTHORIZATION='Bearer good')
        with pytest.raises(TypeError):
            vui.handle_platforms_pubsub(env, {'message': 1})
        env = get_test_web_env('/vui/platforms', HTTP_AUTHORIZATION='Bearer good')
        with pytest.raises(TypeError):
            vui.handle_platforms(env, MagicMock(), {})
        vui._agent.get_user_claims.assert_not_called()


class TestWebsocketRevalidatesToken:
    def _socket(self, agent, authorization):
        ws = VUIWebSocket.__new__(VUIWebSocket)
        app = MagicMock()
        app._agent = agent
        ws.environ = {'PATH_INFO': PUBSUB, 'ws4py.app': app}
        if authorization:
            ws.environ['HTTP_AUTHORIZATION'] = authorization
        ws.close = MagicMock()
        return ws, app

    def test_valid_token_subscribes(self, mock_platform_web_service):
        ws, app = self._socket(mock_platform_web_service, 'Bearer good')
        ws.opened()
        ws.close.assert_not_called()
        app.client_opened.assert_called_once_with(ws, 'devices/campus/building/point', 'good')

    def test_missing_token_closes_socket(self, mock_platform_web_service):
        ws, app = self._socket(mock_platform_web_service, None)
        ws.opened()
        ws.close.assert_called_once()
        app.client_opened.assert_not_called()

    def test_invalid_token_closes_socket(self, mock_platform_web_service):
        mock_platform_web_service.get_user_claims = _reject
        ws, app = self._socket(mock_platform_web_service, 'Bearer forged')
        ws.opened()
        ws.close.assert_called_once()
        app.client_opened.assert_not_called()

    def test_token_without_vui_group_closes_socket(self, mock_platform_web_service):
        mock_platform_web_service.get_user_claims = lambda bearer: {'groups': ['admin']}
        ws, app = self._socket(mock_platform_web_service, 'Bearer admin-only')
        ws.opened()
        ws.close.assert_called_once()
        app.client_opened.assert_not_called()


class TestEndpointDecoratorFailsClosed:
    def test_invalid_token_is_401_not_500(self, vui):
        vui._agent.get_user_claims = _reject
        env = get_test_web_env('/vui/platforms', HTTP_AUTHORIZATION='Bearer forged')
        response = vui.handle_platforms(env, {})
        assert response.status_code == 401

    def test_malformed_authorization_header_is_401(self, vui):
        env = get_test_web_env('/vui/platforms', HTTP_AUTHORIZATION='not-a-bearer-header')
        assert vui.handle_platforms(env, {}).status_code == 401

    @pytest.mark.parametrize("claims", [{}, None, {'groups': None}, {'grant_type': 'refresh_token'}])
    def test_tokens_without_groups_are_403_not_500(self, vui, claims):
        vui._agent.get_user_claims = lambda bearer: claims
        env = get_test_web_env('/vui/platforms', HTTP_AUTHORIZATION='Bearer refresh')
        assert vui.handle_platforms(env, {}).status_code == 403

    def test_every_vui_route_is_wrapped(self, vui):
        for regex, route_type, handler in vui.get_routes():
            assert route_type == 'callable'
            assert handler.__name__ == getattr(handler, '__wrapped__', handler).__name__
            assert getattr(handler, '__wrapped__', None) is not None, f'{handler.__name__} is not @endpoint-wrapped'
