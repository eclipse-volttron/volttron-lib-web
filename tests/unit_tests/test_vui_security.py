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

"""Authorization contract of the VUI RPC proxy: it forwards only what the rpc-allow-list permits and never the
platform services. The pubsub, websocket and endpoint-decorator contracts live in test_vui_auth_contract.py on the
extra_fixes branch."""
import json
import pytest

from unittest.mock import MagicMock

from volttron.client.known_identities import AUTH, CONFIGURATION_STORE, CONTROL, PLATFORM_DRIVER, PLATFORM_WEB
from volttron.services.web.platform_web_service import WebServiceConfig
from volttron.services.web.rpc_proxy_policy import RpcProxyPolicy, RpcAllowListError
from volttron.services.web.vui_endpoints import VUIEndpoints

from web_utils import get_test_web_env, mock_platform_web_service


@pytest.fixture()
def vui(mock_platform_web_service):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.pubsub_manager = MagicMock()
    vui_endpoints.pubsub_manager.publish.return_value = {'number_of_subscribers': 1}
    vui_endpoints._rpc = MagicMock(return_value={'methods': ['a']})
    return vui_endpoints


OPEN = RpcProxyPolicy('*: *')
INI_ALLOW_LIST = """
    platform.historian: query*
    my.app.*: *
    building2: some.agent: get_status, get_config
    build*: other.agent: *
"""
PLATFORM = 'my_instance_name'


def _rpc_env(peer, method=None, http_method='GET', platform=PLATFORM):
    path = f'/vui/platforms/{platform}/agents/{peer}/rpc' + (f'/{method}' if method else '')
    return get_test_web_env(path, method=http_method, HTTP_AUTHORIZATION='Bearer good')


class TestRpcAllowListParsing:
    def test_absent_option_yields_no_entries(self):
        assert RpcProxyPolicy().entries == ()
        assert RpcProxyPolicy('').entries == ()
        assert RpcProxyPolicy('\n   \n').entries == ()

    def test_two_field_line_applies_to_every_platform(self):
        (entry,) = RpcProxyPolicy('platform.historian: query*, get_*').entries
        assert (entry.platform, entry.identity, entry.methods) == ('*', 'platform.historian', ('query*', 'get_*'))

    def test_three_field_line_is_platform_scoped(self):
        (entry,) = RpcProxyPolicy('building2: some.agent: get_status').entries
        assert (entry.platform, entry.identity, entry.methods) == ('building2', 'some.agent', ('get_status',))

    def test_ini_multiline_value_is_parsed_line_by_line(self):
        policy = RpcProxyPolicy(INI_ALLOW_LIST)
        assert [str(e) for e in policy.entries] == ['*: platform.historian: query*', '*: my.app.*: *',
                                                    'building2: some.agent: get_status, get_config',
                                                    'build*: other.agent: *']

    def test_mapping_form_accepts_string_or_list_methods(self):
        policy = RpcProxyPolicy({'platform.historian': 'query*, get_*', 'building2: some.agent': ['get_status']})
        assert [str(e) for e in policy.entries] == ['*: platform.historian: query*, get_*',
                                                    'building2: some.agent: get_status']

    @pytest.mark.parametrize("bad", ['platform.historian', 'platform.historian:', ': query', 'a: b: c: d',
                                     'building2: : get_status', 'platform.historian: ,'])
    def test_malformed_entries_are_rejected(self, bad):
        with pytest.raises(RpcAllowListError):
            RpcProxyPolicy(bad)

    def test_non_string_values_are_rejected(self):
        with pytest.raises(RpcAllowListError):
            RpcProxyPolicy(42)
        with pytest.raises(RpcAllowListError):
            RpcProxyPolicy([42])

    def test_web_service_config_parses_the_ini_option(self):
        config = WebServiceConfig(bind_web_address='http://127.0.0.1:8080', messagebus='zmq',
                                  web_secret_key='unit-test-secret-key', rpc_allow_list=INI_ALLOW_LIST)
        assert config.rpc_allow_list == RpcProxyPolicy(INI_ALLOW_LIST)

    def test_web_service_config_defaults_to_closed(self):
        config = WebServiceConfig(bind_web_address='http://127.0.0.1:8080', messagebus='zmq',
                                  web_secret_key='unit-test-secret-key')
        assert config.rpc_allow_list.entries == ()
        assert not config.rpc_allow_list.is_allowed(PLATFORM, 'my.agent', 'anything')

    def test_web_service_config_rejects_malformed_option(self):
        with pytest.raises(ValueError, match='rpc-allow-list'):
            WebServiceConfig(bind_web_address='http://127.0.0.1:8080', messagebus='zmq',
                             web_secret_key='unit-test-secret-key', rpc_allow_list='no methods here')


class TestRpcProxyPolicyMatching:
    def test_empty_policy_refuses_everything(self):
        policy = RpcProxyPolicy()
        assert not policy.is_allowed(PLATFORM, 'my.agent', 'anything')
        assert not policy.permits_any(PLATFORM, 'my.agent')
        assert policy.filter_methods(PLATFORM, 'my.agent', ['a', 'b']) == []

    @pytest.mark.parametrize("peer, method, allowed", [
        ('platform.historian', 'query', True),
        ('platform.historian', 'query_topic_list', True),
        ('platform.historian', 'insert', False),
        ('my.app.one', 'anything', True),
        ('my.app', 'anything', False),            # 'my.app.*' requires the trailing segment
        ('my.application', 'anything', False),
        ('some.agent', 'get_status', False),      # scoped to building2, not this platform
        ('unlisted.agent', 'get_status', False),
    ])
    def test_identity_and_method_globs(self, peer, method, allowed):
        assert RpcProxyPolicy(INI_ALLOW_LIST).is_allowed(PLATFORM, peer, method) is allowed

    @pytest.mark.parametrize("platform, peer, method, allowed", [
        ('building2', 'some.agent', 'get_status', True),
        ('building2', 'some.agent', 'get_config', True),
        ('building2', 'some.agent', 'set_config', False),
        ('building3', 'some.agent', 'get_status', False),
        ('building3', 'other.agent', 'anything', True),   # 'build*' platform glob
        ('campus', 'other.agent', 'anything', False),
        ('building2', 'platform.historian', 'query', True),  # two-field entries apply everywhere
    ])
    def test_platform_scoping(self, platform, peer, method, allowed):
        assert RpcProxyPolicy(INI_ALLOW_LIST).is_allowed(platform, peer, method) is allowed

    def test_matching_is_case_sensitive_and_anchored(self):
        policy = RpcProxyPolicy('my.agent: get_*')
        assert policy.is_allowed(PLATFORM, 'my.agent', 'get_point')
        assert not policy.is_allowed(PLATFORM, 'my.agent', 'Get_point')
        assert not policy.is_allowed(PLATFORM, 'my.agent', 'forget_point')
        assert not policy.is_allowed(PLATFORM, 'my.agent.two', 'get_point')

    @pytest.mark.parametrize("peer, method", [
        (AUTH, 'create_or_merge_agent_authz'), (AUTH, 'list_credentials'),
        (PLATFORM_WEB, 'register_path_route'), (PLATFORM_WEB, 'get_user_claims'),
        (CONFIGURATION_STORE, 'delete_store'), (CONFIGURATION_STORE, 'manage_list_stores'),
        (PLATFORM_DRIVER, 'set_point'), (PLATFORM_DRIVER, 'get_point'),
        (CONTROL, 'install_agent'), (CONTROL, 'remove_agent'), (CONTROL, 'shutdown'), (CONTROL, 'stop_platform'),
        (CONTROL, 'clear_status'), (CONTROL, 'prioritize_agent'), (CONTROL, 'tag_agent'),
    ])
    def test_denylist_overrides_a_fully_open_allow_list(self, peer, method):
        assert not OPEN.is_allowed(PLATFORM, peer, method)
        assert OPEN.is_denied(peer, method)

    @pytest.mark.parametrize("peer", [AUTH, PLATFORM_WEB, CONFIGURATION_STORE, PLATFORM_DRIVER])
    def test_denied_peers_permit_nothing(self, peer):
        assert not OPEN.permits_any(PLATFORM, peer)
        assert OPEN.filter_methods(PLATFORM, peer, ['get_point']) == []

    def test_open_allow_list_reaches_everything_else(self):
        assert OPEN.is_allowed(PLATFORM, CONTROL, 'status_agents')
        assert OPEN.is_allowed(PLATFORM, CONTROL, 'list_agents')
        assert OPEN.is_allowed('any.platform', 'my.agent', 'anything')
        assert OPEN.permits_any(PLATFORM, CONTROL)
        assert OPEN.filter_methods(PLATFORM, CONTROL, ['list_agents', 'shutdown', 'install_agent']) == ['list_agents']


class TestRpcProxyEndpoints:
    def test_default_policy_closes_the_proxy(self, vui):
        assert vui.rpc_policy.entries == ()
        assert vui.handle_platforms_agents_rpc(_rpc_env('my.agent'), {}).status_code == 403
        assert vui.handle_platforms_agents_rpc_method(_rpc_env('my.agent', 'anything'), {}).status_code == 403
        assert vui.handle_platforms_agents_rpc_method(_rpc_env('my.agent', 'anything', 'POST'),
                                                      {'args': [1]}).status_code == 403
        vui._rpc.assert_not_called()

    @pytest.mark.parametrize("peer, method", [(AUTH, 'create_or_merge_agent_authz'), (PLATFORM_WEB, 'get_user_claims'),
                                              (CONFIGURATION_STORE, 'manage_delete_store'),
                                              (PLATFORM_DRIVER, 'set_point'), (CONTROL, 'shutdown'),
                                              (CONTROL, 'install_agent')])
    def test_denied_method_call_is_403_and_not_forwarded(self, vui, peer, method):
        vui.rpc_policy = OPEN
        response = vui.handle_platforms_agents_rpc_method(_rpc_env(peer, method, 'POST'), {'args': [1]})
        assert response.status_code == 403
        assert 'not permitted' in json.loads(response.response[0])['error']
        vui._rpc.assert_not_called()

    @pytest.mark.parametrize("peer", [AUTH, PLATFORM_WEB, CONFIGURATION_STORE, PLATFORM_DRIVER])
    def test_denied_peer_inspection_is_403(self, vui, peer):
        vui.rpc_policy = OPEN
        assert vui.handle_platforms_agents_rpc(_rpc_env(peer), {}).status_code == 403
        assert vui.handle_platforms_agents_rpc_method(_rpc_env(peer, 'some_method'), {}).status_code == 403
        vui._rpc.assert_not_called()

    def test_unlisted_peer_is_403_without_inspection(self, vui):
        vui.rpc_policy = RpcProxyPolicy(INI_ALLOW_LIST)
        assert vui.handle_platforms_agents_rpc(_rpc_env('unlisted.agent'), {}).status_code == 403
        assert vui.handle_platforms_agents_rpc_method(_rpc_env('unlisted.agent', 'get_status'), {}).status_code == 403
        vui._rpc.assert_not_called()

    def test_allowed_call_is_forwarded(self, vui):
        vui.rpc_policy = OPEN
        vui._rpc = MagicMock(return_value=[['1', '', [10, None]]])
        response = vui.handle_platforms_agents_rpc_method(_rpc_env(CONTROL, 'status_agents', 'POST'), {})
        assert response.status_code == 200
        vui._rpc.assert_called_once_with(CONTROL, 'status_agents', external_platform=PLATFORM)

    def test_allowed_call_with_args_is_forwarded(self, vui):
        vui.rpc_policy = RpcProxyPolicy(INI_ALLOW_LIST)
        vui._rpc = MagicMock(return_value={'ok': True})
        response = vui.handle_platforms_agents_rpc_method(_rpc_env('platform.historian', 'query', 'POST'),
                                                          {'args': ['some/topic'], 'count': 5})
        assert response.status_code == 200
        vui._rpc.assert_called_once_with('platform.historian', 'query', 'some/topic', count=5,
                                         external_platform=PLATFORM)

    def test_method_inspection_is_gated_by_the_same_rule(self, vui):
        vui.rpc_policy = RpcProxyPolicy(INI_ALLOW_LIST)
        vui._rpc = MagicMock(return_value={'params': {}})
        assert vui.handle_platforms_agents_rpc_method(_rpc_env('platform.historian', 'insert'), {}).status_code == 403
        vui._rpc.assert_not_called()
        assert vui.handle_platforms_agents_rpc_method(_rpc_env('platform.historian', 'query'), {}).status_code == 200
        vui._rpc.assert_called_once_with('platform.historian', 'query.inspect', external_platform=PLATFORM)

    def test_method_listing_is_filtered_to_allowed_methods(self, vui):
        vui.rpc_policy = RpcProxyPolicy(INI_ALLOW_LIST)
        vui._rpc = MagicMock(return_value={'methods': ['query', 'query_topic_list', 'insert']})
        response = vui.handle_platforms_agents_rpc(_rpc_env('platform.historian'), {})
        assert response.status_code == 200
        links = json.loads(response.response[0])['links']
        assert set(links) == {'query', 'query_topic_list'}
        assert links['query'] == f'/vui/platforms/{PLATFORM}/agents/platform.historian/rpc/query'

    def test_control_listing_omits_denied_lifecycle_methods(self, vui):
        vui.rpc_policy = OPEN
        vui._rpc = MagicMock(return_value={'methods': ['list_agents', 'status_agents', 'shutdown', 'install_agent']})
        response = vui.handle_platforms_agents_rpc(_rpc_env(CONTROL), {})
        assert response.status_code == 200
        assert set(json.loads(response.response[0])['links']) == {'list_agents', 'status_agents'}

    def test_platform_scoped_entry_only_applies_to_that_platform(self, vui):
        vui.rpc_policy = RpcProxyPolicy(INI_ALLOW_LIST)
        vui._rpc = MagicMock(return_value='ok')
        assert vui.handle_platforms_agents_rpc_method(
            _rpc_env('some.agent', 'get_status', 'POST', platform='building2'), {}).status_code == 200
        vui._rpc.assert_called_once_with('some.agent', 'get_status', external_platform='building2')
        vui._rpc.reset_mock()
        assert vui.handle_platforms_agents_rpc_method(
            _rpc_env('some.agent', 'get_status', 'POST', platform='building3'), {}).status_code == 403
        vui._rpc.assert_not_called()

    def test_policy_comes_from_the_web_service_config(self, mock_platform_web_service):
        mock_platform_web_service.config.rpc_allow_list = INI_ALLOW_LIST
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        assert vui_endpoints.rpc_policy == RpcProxyPolicy(INI_ALLOW_LIST)
