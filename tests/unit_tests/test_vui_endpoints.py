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

import json
import mock
import pytest
import re

from unittest.mock import MagicMock
from werkzeug import Response

# mock.patch('volttron.services.web.vui_endpoints.endpoint', lambda x: x).start()

from volttron.client.known_identities import CONFIGURATION_STORE, CONTROL, PLATFORM_DRIVER, PLATFORM_HEALTH

from volttron.services.web.rpc_proxy_policy import RpcProxyPolicy
from volttron.lib.tree import DeviceTree
from volttron.services.web.vui_endpoints import VUIEndpoints
from volttron.utils.jsonrpc import RemoteError


from web_utils import get_test_web_env, mock_platform_web_service

import logging  # TODO: Shouldn't need logger once this is complete.
_log = logging.getLogger()

ACTIVE_ROUTES = {
    'vui': {'endpoint-active': True,
            'platforms': {'endpoint-active': True,
                          'agents': {'endpoint-active': True,
                                     'configs': {'endpoint-active': True},
                                     'enabled': {'endpoint-active': True},
                                     'front-ends': {'endpoint-active': False},
                                     'health': {'endpoint-active': False},
                                     'pubsub': {'endpoint-active': False},
                                     'rpc': {'endpoint-active': True},
                                     'running': {'endpoint-active': True},
                                     'status': {'endpoint-active': True},
                                     'tag': {'endpoint-active': True}
                                     },
                          'devices': {'endpoint-active': True},
                          'status': {'endpoint-active': False}
                          },
            'historians': {'endpoint-active': False}
            }
}

DEVICE_LIST = ['Campus/Building1/Fake1', 'Campus/Building2/Fake1', 'Campus/Building3/Fake1']
DEVICE_CONFIG = {'driver_config': {}, 'interval': 60, 'timezone': 'US/Pacific', 'driver_type': 'fakedriver',
                 'publish_breadth_first_all': False, 'publish_depth_first': False, 'publish_breadth_first': False,
                 'campus': 'campus', 'building': 'building', 'unit': 'fake_device'}
REGISTRY_CONFIG = [
    {'Volttron Point Name': 'SampleWritableFloat1', 'Units': 'PPM', 'Units Details': '1000.00 (default)',
     'Writable': 'TRUE', 'Starting Value': '10', 'Type': 'float',
     'Notes': 'Setpoint to enable demand control ventilation'},
    {'Volttron Point Name': 'SampleBool1', 'Units': 'On / Off', 'Units Details': 'on/off', 'Writable': 'FALSE',
     'Starting Value': 'TRUE', 'Type': 'boolean', 'Notes': 'Status indidcator of cooling stage 1'}
]


def _build_device_tree() -> DeviceTree:
    """Build the device tree the same way DeviceTree.from_store does, without a config store."""
    devices = [f'devices/{d}' for d in DEVICE_LIST]
    tree = DeviceTree(devices)
    for d in devices:
        # Node.topic reads data['topic'], which TopicTree.add_node set on creation; keep it when replacing data.
        tree.update_node(d, data={'config': dict(DEVICE_CONFIG), 'segment_type': 'DEVICE',
                                  'topic': d[len('devices/'):]})
        for pnt in REGISTRY_CONFIG:
            pnt = dict(pnt)
            point_name = pnt.pop('Volttron Point Name')
            n = tree.create_node(point_name, f"{d}/{point_name}", parent=d, data=pnt)
            n.data['segment_type'] = 'POINT'
    return tree


def gen_response_codes(valid_codes: list, exclude: list = None):
    exclude = exclude if exclude else []
    http_methods = ('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH')
    valid = [(f'{code}', '200') for code in http_methods if code in valid_codes]
    invalid = [(f'{code}', '501') for code in http_methods if code not in valid_codes and code not in exclude]
    return valid + invalid


def check_response_codes(response, status):
    assert isinstance(response, Response)
    assert status in response.status


def check_links_return(response, keys: list = None, leading_path: str = None):
    body = json.loads(response.response[0])
    assert isinstance(body, dict)
    assert isinstance(body['links'], dict)
    if keys:
        assert len(keys) == len(body['links'].keys())
        assert all([key in body['links'].keys() for key in keys])
    if keys and leading_path:
        assert all([re.match(f'{leading_path}/[^/]+/?$', value) for value in body['links'].values()])
    return body['links']


def test_get_routes(mock_platform_web_service):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    routes = vui_endpoints.get_routes()
    assert isinstance(routes, list)
    assert all([isinstance(route, tuple) for route in routes])
    assert all([isinstance(route[0], re.Pattern) for route in routes])
    assert all([route[1] == 'callable' for route in routes])
    assert all([hasattr(vui_endpoints, route[2].__name__) and callable(getattr(vui_endpoints, route[2].__name__))
                for route in routes])


@pytest.mark.parametrize('platforms', [
    ['my_instance_name', 'foo', 'bar', 'baz'],
    ['foo', 'bar', 'baz'],
    list(),
    FileNotFoundError,
    Exception
])
def test_get_platforms(mock_platform_web_service, platforms):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    if type(platforms) is list:
        external_platforms_discovery_json = {p: {} for p in platforms}
        with mock.patch('builtins.open', mock.mock_open(read_data=json.dumps(external_platforms_discovery_json))):
            this_instance = mock_platform_web_service.core.instance_name
            if this_instance not in platforms:
                platforms.insert(0, this_instance)
            retval = vui_endpoints._get_platforms()
            assert retval == platforms
    else:
        with mock.patch('builtins.open', mock.mock_open()) as mocked_open:
            mocked_open.side_effect = platforms
            retval = vui_endpoints._get_platforms()
            assert retval == [vui_endpoints._agent.core.instance_name]


@pytest.mark.parametrize('segments, expected_keys, expected_links',
                         [
                             (['vui'], ['platforms'], {'platforms': '/foo/bar/platforms'}),
                             (['vui', 'platforms'], ['agents', 'devices'],
                              {'agents': '/foo/bar/agents', 'devices': '/foo/bar/devices'}),
                             (['vui', 'platforms', 'agents'], ['configs', 'enabled', 'rpc', 'running', 'status', 'tag'],
                              {'rpc': '/foo/bar/rpc', 'configs': '/foo/bar/configs', 'enabled': '/foo/bar/enabled',
                              'running': '/foo/bar/running', 'status': '/foo/bar/status', 'tag': '/foo/bar/tag'}),
                             (['vui', 'platforms', 'agents', 'configs'], [], {}),
                             (['vui', 'platforms', 'agents', 'rpc'], [], {}),
                             (['vui', 'platforms', 'devices'], [], {}),
                             (['vui', 'platforms', 'status'], [], {}),
                             (['vui', 'historians'], [], {}),
                         ])
def test_find_active_sub_routes(mock_platform_web_service, segments, expected_keys, expected_links):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.active_routes = ACTIVE_ROUTES
    assert vui_endpoints._find_active_sub_routes(segments) == expected_keys
    assert vui_endpoints._find_active_sub_routes(segments, '/foo/bar', False) == expected_links
    assert vui_endpoints._find_active_sub_routes(segments, '/foo/bar') == {'links': expected_links}


@pytest.mark.parametrize('values, expected',
                         [
                             ([], None),
                             ('true', True),
                             ('false', False),
                             (['True', 'true', 'T', 't', '1', 'F', 'f', 1, '2', ''],
                              [True, True, True, True, True, False, False, True, False, False])
                         ])
def test_to_bool(mock_platform_web_service, values, expected):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    assert vui_endpoints._to_bool(values) == expected


@pytest.mark.parametrize('option_segments, expected_links',
                         [
                             ([], {}),
                             (['foo', 'bar', 'baz'],
                              {'foo': '/foo/bar/foo', 'bar': '/foo/bar/bar', 'baz': '/foo/bar/baz'})
                         ])
def test_links(mock_platform_web_service, option_segments, expected_links):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    assert vui_endpoints._links('/foo/bar', option_segments, False) == expected_links
    assert vui_endpoints._links('/foo/bar', option_segments) == {'links': expected_links}


def test_rpc(mock_platform_web_service):
    def rpc_caller(peer, method, *args, **kwargs):
        class MockAsyncResponse:
            @staticmethod
            def get(timeout=5):
                return True
        if kwargs.get('external_platform') and kwargs['external_platform'] == 'my_instance_name':
            raise Exception('Passed this instance as external platform.')
        return MockAsyncResponse

    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._agent.vip.rpc.call = rpc_caller
    assert vui_endpoints._rpc('a_vip_id', 'some_method', external_platform='my_instance_name') is True
    assert vui_endpoints._rpc('a_vip_id', 'some_method', external_platform='other_platform') is True


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_vui_root(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui', method=method, HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    response = vui_endpoints.handle_vui_root(env, {})
    check_response_codes(response, status)
    if '200' in response.status:
        check_links_return(response)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms', method=method, HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    response = vui_endpoints.handle_platforms(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('platforms',
                         [
                             ['my_instance_name', 'foo', 'bar', 'baz'],
                             ['foo', 'bar', 'baz'],
                             list(),
                             FileNotFoundError,
                             Exception
                         ])
def test_handle_platforms_response(mock_platform_web_service, platforms):
    path = '/vui/platforms'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    if type(platforms) is list:
        external_platforms_discovery_json = {p: {} for p in platforms}
        with mock.patch('builtins.open', mock.mock_open(read_data=json.dumps(external_platforms_discovery_json))):
            this_instance = mock_platform_web_service.core.instance_name
            if this_instance not in platforms:
                platforms.insert(0, this_instance)
            response = vui_endpoints.handle_platforms(env, {})
            links = check_links_return(response, platforms, path)
    else:
        with mock.patch('builtins.open', mock.mock_open()) as mocked_open:
            mocked_open.side_effect = platforms
            response = vui_endpoints.handle_platforms(env, {})
            links = check_links_return(response, [vui_endpoints.local_instance_name], path)
    assert '200' in response.status
    assert list(links.keys())[0] == vui_endpoints.local_instance_name


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_platform_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name', method=method, HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    response = vui_endpoints.handle_platforms_platform(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize("platform", ['my_instance_name', 'other_instance_name', 'not_a_platform'])
def test_handle_platforms_platform_response(mock_platform_web_service, platform):
    path = f'/vui/platforms/{platform}'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    with mock.patch('builtins.open', mock.mock_open(read_data=json.dumps({'other_instance_name': {}}))):
        response = vui_endpoints.handle_platforms_platform(env, {})
        if platform in ['my_instance_name', 'other_instance_name']:
            check_links_return(response, leading_path=path)
        else:
            assert '400' in response.status


def _mock_agents_rpc(peer, meth, *args, external_platform=None, **kwargs):
    list_of_agents = [{'name': 'rn1', 'uuid': '1', 'tag': 'r1', 'identity': 'run1', 'priority': None},
                      {'name': 'rn2', 'uuid': '2', 'tag': 'r2', 'identity': 'run2', 'priority': 50},
                      {'name': 'stp1', 'uuid': '3', 'tag': 'st1', 'identity': 'stopped1', 'priority': None},
                      {'name': 'stp2', 'uuid': '4', 'tag': 'st2', 'identity': 'stopped2', 'priority': 35}]
    config_definition_list = [{'identity': 'run1', 'configs': {'config1': {'setting1': 1, 'setting2': 2},
                                                               'config2': {'setting1': 3, 'setting2': 4}}},
                              {'identity': 'run2', 'configs': {'config1': {'setting1': 5, 'setting2': 6},
                                                               'config2': {'setting1': 7, 'setting2': 8}}}]
    # A CSV config kept outside config_definition_list so the list/links expectations above are unchanged.
    csv_configs = {('run1', 'points.csv'): ('Point Name,Value\nA,1\n', [{'Point Name': 'A', 'Value': '1'}])}
    if peer == CONFIGURATION_STORE and meth in ('get_config', 'get_metadata'):
        if (args[0], args[1]) in csv_configs:
            raw, parsed = csv_configs[(args[0], args[1])]
            return parsed if meth == 'get_config' else {'type': 'csv', 'modified': None, 'data': raw}
        config_list = [a['configs'].get(args[1]) for a in config_definition_list if a['identity'] == args[0]]
        if not config_list or config_list == [None]:
            raise RemoteError(f'''builtins.KeyError('No configuration file \"{args[1]}\" for VIP IDENTIY {args[0]}')''',
                              exc_info={"exc_type": '', "exc_args": []})
        parsed = config_list[0]
        return parsed if meth == 'get_config' else {'type': 'json', 'modified': None, 'data': json.dumps(parsed)}
    elif peer == CONFIGURATION_STORE and meth == 'list_configs':
        config_list = [a['configs'].keys() for a in config_definition_list if a['identity'] == args[0]]
        return config_list[0] if config_list else []
    elif peer == CONFIGURATION_STORE and meth == 'list_stores':
        return [a['identity'] for a in config_definition_list]
    elif peer == CONTROL and meth == 'list_agents':
        return list_of_agents
    elif peer == CONTROL and meth == 'identity_exists':
        uuid = [a['uuid'] for a in list_of_agents if a['identity'] == args[0]]
        return uuid[0] if uuid else None
    elif peer == CONTROL and meth == 'status_agents':
        return [['1', '', [10, None]], ['2', '', [11, None]], ['4', '', [12, 0]]]
    elif peer == CONTROL and meth == 'peerlist':
        return ['run1', 'run2', 'hid1', 'hid2']
    elif peer == PLATFORM_HEALTH and meth == 'get_platform_health':
        return {i: {'peer': i, 'service_agent': i.startswith('hid'), 'connected': '2026-10-21T00:00:00',
                    'last_heartbeat': '2026-10-21T00:00:05', 'message': 'GOOD'} for i in ['run1', 'run2', 'hid1', 'hid2']}
    elif peer == CONTROL and meth in ('start_agent', 'stop_agent', 'restart_agent', 'prioritize_agent'):
        return None
    elif peer == CONTROL and meth == 'inspect':
        return {'methods': ['list_agents', 'peerlist', 'status_agents']}
    elif peer == CONTROL and meth == 'status_agents.inspect':
        return {'params': {}}
    elif meth == 'inspect':
        return {'methods': ['some_method']}
    elif peer == 'agents_rpc' and meth == 'kw_only':
        return [kwargs['foo'], kwargs['bar']]
    elif peer == 'agents_rpc' and meth == 'args_and_kw':
        return [*args, kwargs['foo'], kwargs['bar']]
    elif peer == 'agents_rpc' and meth == 'args_only':
        return [*args]


@pytest.mark.parametrize(
    'agent_state, include_hidden, expected', [
        ('running', False, ['run1', 'run2']),
        ('running', True, ['run1', 'run2', 'hid1', 'hid2']),
        ('installed', False, ['run1', 'run2', 'stopped1', 'stopped2']),
        ('installed', True, ['run1', 'run2', 'stopped1', 'stopped2', 'hid1', 'hid2']),
        ('packaged', False, ['packaged1', 'packaged2']),
        ('packaged', True, ['packaged1', 'packaged2'])
    ]
)
def test_get_agents(mock_platform_web_service, agent_state, include_hidden, expected):
    with mock.patch('os.listdir') as mocked_dir:
        mocked_dir.return_value = ['packaged1.whl', 'packaged2.whl']
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        vui_endpoints._rpc = _mock_agents_rpc
        result = vui_endpoints._get_agents('my_instance_name', agent_state, include_hidden)
    assert isinstance(result, list)
    assert result == expected


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_agents_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents', method=method, HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize(
    'agent_state, include_hidden, expected', [
        ('running', False, ['run1', 'run2']),
        ('running', True, ['run1', 'run2', 'hid1', 'hid2']),
        ('installed', False, ['run1', 'run2', 'stopped1', 'stopped2']),
        ('installed', True, ['run1', 'run2', 'stopped1', 'stopped2', 'hid1', 'hid2'])
    ]
)
@pytest.mark.parametrize("platform", ['my_instance_name', 'other_instance_name', 'not_a_platform'])
def test_handle_platforms_agents_response(mock_platform_web_service, platform, agent_state, include_hidden, expected):
    path = f'/vui/platforms/{platform}/agents'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    env['QUERY_STRING'] = f'agent-state={agent_state}&include-hidden={str(include_hidden).lower()}'
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    with mock.patch('builtins.open', mock.mock_open(read_data=json.dumps({'other_instance_name': {}}))):
        response = vui_endpoints.handle_platforms_agents(env, {})
        if platform in ['my_instance_name', 'other_instance_name']:
            check_links_return(response, keys=expected, leading_path=path)
        else:
            assert '400' in response.status


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_agents_agent_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/agent_vip', method=method,
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_agent(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', ['configs', 'enabled', 'rpc', 'running', 'status', 'tag']),
    ('stopped1', ['configs', 'enabled', 'running', 'status', 'tag']),
    ('not.installed.agent', ['configs'])
    ])
def test_handle_platforms_agents_agent_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.active_routes = ACTIVE_ROUTES
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_agent(env, {})
    check_links_return(response, keys=expected, leading_path=path)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], ['POST', 'DELETE']))
def test_handle_platforms_agents_configs_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/configs', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], ['PUT', 'DELETE']))
def test_handle_platforms_agents_configs_config_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/configs/config1', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize("vip_identity, expected", [
    ('-', ["run1", "run2"]),
    ('run1', {"links": {"config1": "/vui/platforms/my_instance_name/agents/run1/configs/config1",
                                "config2": "/vui/platforms/my_instance_name/agents/run1/configs/config2"}}),
    ('does_not_exist',  {"links": {}})  #needs to be changed as code is changed
])
def test_handle_platforms_agents_configs_get_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/configs'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize("vip_identity, config_name, expected", [
    ('run1', 'config1', {'setting1': 1, 'setting2': 2}),
    ('run2', 'config2', {'setting1': 7, 'setting2': 8}),
    ('does_not_exist', 'config1',
     {"Error": "builtins.KeyError('No configuration file \"config1\" for VIP IDENTIY does_not_exist')"}),
    ('run1', 'does_not_exist',
     {"Error": "builtins.KeyError('No configuration file \"does_not_exist\" for VIP IDENTIY run1')"})
   ])
def test_handle_platforms_agents_configs_config_get_response(mock_platform_web_service, vip_identity, config_name,
                                                             expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/configs/{config_name}'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize('config_name, accept, status, content_type, body', [
    ('config1', None, 200, 'application/json', '{"setting1": 1, "setting2": 2}'),
    ('config1', '*/*', 200, 'application/json', '{"setting1": 1, "setting2": 2}'),
    ('config1', 'text/csv, application/json;q=0.5', 200, 'application/json', '{"setting1": 1, "setting2": 2}'),
    ('points.csv', None, 200, 'application/json', '[{"Point Name": "A", "Value": "1"}]'),
    ('points.csv', 'text/csv', 200, 'text/csv', 'Point Name,Value\nA,1\n'),
    ('points.csv', 'text/plain', 200, 'text/plain', 'Point Name,Value\nA,1\n'),
    ('config1', 'text/plain', 200, 'text/plain', '{"setting1": 1, "setting2": 2}'),
    ('config1', 'text/*', 200, 'text/plain', '{"setting1": 1, "setting2": 2}'),
    ('config1', 'text/csv', 406, 'application/json', None),
    ('config1', 'application/xml', 406, 'application/json', None),
])
def test_handle_platforms_agents_configs_config_get_accept(mock_platform_web_service, config_name, accept, status,
                                                           content_type, body):
    path = f'/vui/platforms/my_instance_name/agents/run1/configs/{config_name}'
    headers = {'HTTP_ACCEPT': accept} if accept is not None else {}
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo', **headers)
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    assert response.status_code == status
    assert response.content_type.startswith(content_type)
    if body is not None:
        assert response.get_data(as_text=True) == body
    if status == 406:
        assert 'Error' in json.loads(response.get_data(as_text=True))
    if content_type == 'application/json' and status == 200:
        vui_endpoints._rpc.assert_called_once_with(CONFIGURATION_STORE, 'get_config', 'run1', config_name, raw=False,
                                                   external_platform='my_instance_name')


@pytest.mark.parametrize('vip_identity, config_name, data_given, data_passed, config_type, status', [
    ('run1', 'config', {"setting1": 30, "setting2": 0}, '{"setting1": 30, "setting2": 0}', 'application/json',
     '204'),
    ('run1', 'config', '"setting1", 30, "setting2", 0', '"setting1", 30, "setting2", 0', 'text/csv',
     '204'),
    ('run1', 'config', '"setting1" 30 "setting2" 0', '"setting1" 30 "setting2" 0', 'text/plain',
     '204'),
    ('run1', 'config', "something else", "something else", 'invalid_type', '400')
])
def test_handle_platforms_agents_configs_config_put_response(mock_platform_web_service, vip_identity, config_name,
                                                             data_given, data_passed, config_type,
                                                             status):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/configs/{config_name}'
    env = get_test_web_env(path, method='PUT', CONTENT_TYPE=config_type, HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, data_given)
    check_response_codes(response, status)
    config_type = re.search(r'([^\/]+$)', config_type).group() if config_type in ['application/json',
                                                                                  'text/csv'] else 'raw'
    if status == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONFIGURATION_STORE, 'set_config', vip_identity, config_name,
                                                       data_passed, config_type, external_platform='my_instance_name')])
    elif status == '400':
        assert json.loads(response.response[0]) == \
               {"Error": "The configuration type can only be 'JSON', 'CSV' and 'RAW.'"}



@pytest.mark.parametrize('vip_identity, config_name, data_given, data_passed, config_type, status', [
    ('run1', 'config', {'setting1': 30, 'setting2': 0}, {'setting1': 30, 'setting2': 0}, 'application/json',
     '201'),
    ('run1', 'config', "'setting1', 30, 'setting2', 0", "'setting1', 30, 'setting2', 0", 'text/csv',
     '201'),
    ('run1', 'config', "'setting1'  30 'setting2' 0", "'setting1' 30 'setting2' 0", 'text/plain',
     '201'),
    ('run1', 'config', "something else", "something else", 'invalid_type', '400'),
    ('run1', 'config1', {'setting1': 30, 'setting2': 0}, {'setting1': 30, 'setting2': 0}, 'application/json', '409')
])
def test_handle_platforms_agents_configs_post_response(mock_platform_web_service, vip_identity, config_name,
                                                             data_given, data_passed, config_type,
                                                             status):
    query_string = f'config-name={config_name}' if config_name else ''
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/configs'
    env = get_test_web_env(path, method='POST', query_string=query_string, CONTENT_TYPE=config_type,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, data_given)
    check_response_codes(response, status)
    if status == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONFIGURATION_STORE, 'set_config', vip_identity, config_name,
                                                       data_passed, config_type, external_platform='my_instance_name')])
    elif status == '400':
        assert json.loads(response.response[0]) == \
               {"Error": "The configuration type can only be 'JSON', 'CSV' and 'RAW.'"}
    elif status == '409':
        assert json.loads(response.response[0]) == \
               {'Error': f'Configuration: "{config_name}" already exists for agent: "{vip_identity}"'}


def _platform_refusal(method):
    return RemoteError(f"User platform.web does not have access to call platform.config_store.{method} ",
                       exc_type='volttron.types.auth.AuthException',
                       exc_args=[f'User platform.web does not have access to call platform.config_store.{method} '])


@pytest.mark.parametrize('http_method, path, data, denied_rpc', [
    ('PUT', '/vui/platforms/my_instance_name/agents/run1/configs/config', {'a': 1}, 'set_config'),
    ('POST', '/vui/platforms/my_instance_name/agents/run1/configs?config-name=new', {'a': 1}, 'set_config'),
    ('DELETE', '/vui/platforms/my_instance_name/agents/run1/configs/config1', {}, 'delete_config'),
    ('DELETE', '/vui/platforms/my_instance_name/agents/run1/configs?all=true', {}, 'delete_store'),   # past the 409 guard
])
def test_handle_platforms_agents_configs_platform_refusal_is_403(mock_platform_web_service, http_method, path, data,
                                                                 denied_rpc):
    """platform.web lacking the config-store capability is the web service's privilege problem, not the user's
    credentials (401) nor a bad request (400): 403 with the platform's reason."""
    path, _, query = path.partition('?')

    def refusing_rpc(peer, meth, *args, **kwargs):
        if peer == CONFIGURATION_STORE and meth == denied_rpc:
            raise _platform_refusal(denied_rpc)
        return _mock_agents_rpc(peer, meth, *args, **kwargs)

    env = get_test_web_env(path, method=http_method, query_string=query, CONTENT_TYPE='application/json',
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=refusing_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, data)
    assert response.status_code == 403
    body = json.loads(response.get_data(as_text=True))
    assert 'not authorized by the platform' in body['error']
    assert body['detail'] == f'User platform.web does not have access to call platform.config_store.{denied_rpc}'


def test_handle_platforms_agents_configs_other_remote_errors_keep_their_codes(mock_platform_web_service):
    """A non-authorization RemoteError is still 400 on DELETE (handler) and 500 on PUT (decorator)."""
    def failing_rpc(peer, meth, *args, **kwargs):
        if meth in ('set_config', 'delete_config'):
            raise RemoteError("builtins.ValueError('bad')", exc_type='builtins.ValueError', exc_args=['bad'])
        return _mock_agents_rpc(peer, meth, *args, **kwargs)
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=failing_rpc)
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/configs/config1', method='DELETE',
                           HTTP_AUTHORIZATION='Bearer foo')
    assert vui_endpoints.handle_platforms_agents_configs(env, {}).status_code == 400
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/configs/config1', method='PUT',
                           CONTENT_TYPE='application/json', HTTP_AUTHORIZATION='Bearer foo')
    assert vui_endpoints.handle_platforms_agents_configs(env, {'a': 1}).status_code == 500


@pytest.mark.parametrize('vip_identity_given, vip_identity_passed, query, status', [
    ('run1', 'run1', '', '409'),                 # run1 still holds config1 and config2
    ('run1', 'run1', 'all=true', '204'),         # explicit consent removes them with the store
    ('stopped1', 'stopped1', '', '204'),         # an empty store needs no consent
])
def test_handle_platforms_agents_configs_delete_response(mock_platform_web_service, vip_identity_given,
                                                         vip_identity_passed, query, status):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity_given}/configs'
    env = get_test_web_env(path, method='DELETE', query_string=query, HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    check_response_codes(response, status)
    delete_calls = [c for c in vui_endpoints._rpc.call_args_list if c.args[:2] == (CONFIGURATION_STORE, 'delete_store')]
    if status == '204':
        assert delete_calls == [mock.call(CONFIGURATION_STORE, 'delete_store', vip_identity_passed,
                                          external_platform='my_instance_name')]
    else:
        assert not delete_calls
        body = json.loads(response.get_data(as_text=True))
        assert 'all=true' in body['error'] and body['configs'] == ['config1', 'config2']


@pytest.mark.parametrize('vip_identity, config_name_given, config_name_passed, status', [
    ('run1', 'config1', 'config1', '204')
])
def test_handle_platforms_agents_configs_config_delete_response(mock_platform_web_service, vip_identity,
                                                                config_name_given, config_name_passed, status):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/configs/{config_name_given}'
    env = get_test_web_env(path, method='DELETE', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_configs(env, {})
    check_response_codes(response, status)
    if status == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONFIGURATION_STORE, 'delete_config', vip_identity,
                                                       config_name_passed, external_platform='my_instance_name')])


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], ['PUT', 'DELETE']))
def test_handle_platforms_agents_enabled_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/enabled', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_enabled(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', {'status': False, 'priority': None}),
    ('run2', {'status': True, 'priority': 50}),
    ('stopped2', {'status': True, 'priority': 35}),
    ('not_exist', {'error': 'Agent "not_exist" not found.'})])
def test_handle_platforms_agents_enabled_get_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/enabled'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_enabled(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize('priority_given, priority_passed, expected', [
    ('30', '30', '204'),
    (None, '50', '204'),
    ('-1', None, '400'),
    ('100', None, '400'),
    ('foo', None, '400')
])
def test_handle_platforms_agents_enabled_put_response(mock_platform_web_service, priority_given, priority_passed,
                                                      expected):
    query_string = f'priority={priority_given}' if priority_given else ''
    path = f'/vui/platforms/my_instance_name/agents/run1/enabled'
    env = get_test_web_env(path, method='PUT', query_string=query_string, HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_enabled(env, {})
    check_response_codes(response, expected)
    if expected == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', 'run1',
                                                       external_platform='my_instance_name'),
                                             mock.call(CONTROL, 'prioritize_agent', '1', priority_passed,
                                                       external_platform='my_instance_name')])


def test_handle_platforms_agents_enabled_delete_response(mock_platform_web_service):
    path = f'/vui/platforms/my_instance_name/agents/run1/enabled'
    env = get_test_web_env(path, method='DELETE', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_enabled(env, {})
    check_response_codes(response, '204')
    vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', 'run1',
                                                   external_platform='my_instance_name'),
                                         mock.call(CONTROL, 'prioritize_agent', '1', None,
                                                   external_platform='my_instance_name')])


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_agents_rpc_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/agent_vip/rpc', method=method,
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.rpc_policy = RpcProxyPolicy('*: *')  # these tests cover the handlers, not the allow-list
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_rpc(env, {})
    check_response_codes(response, status)


def test_handle_platforms_agents_rpc_response(mock_platform_web_service):
    path = f'/vui/platforms/my_instance_name/agents/{CONTROL}/rpc'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.rpc_policy = RpcProxyPolicy('*: *')  # these tests cover the handlers, not the allow-list
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_rpc(env, {})
    check_links_return(response, ['list_agents', 'peerlist', 'status_agents'], leading_path=path)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET', 'POST']))
def test_handle_platforms_agents_rpc_method_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env(f'/vui/platforms/my_instance_name/agents/{CONTROL}/rpc/status_agents', method=method,
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.rpc_policy = RpcProxyPolicy('*: *')  # these tests cover the handlers, not the allow-list
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_rpc_method(env, {})
    check_response_codes(response, status)


def test_handle_platforms_rpc_method_get_response(mock_platform_web_service):
    env = get_test_web_env(f'/vui/platforms/my_instance_name/agents/{CONTROL}/rpc/status_agents', method='GET',
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.rpc_policy = RpcProxyPolicy('*: *')  # these tests cover the handlers, not the allow-list
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_rpc_method(env, {})
    body = json.loads(response.response[0])
    assert isinstance(body, dict)
    assert isinstance(body['params'], dict)


def test_handle_platforms_rpc_method_post_response(mock_platform_web_service):
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints.rpc_policy = RpcProxyPolicy('*: *')  # these tests cover the handlers, not the allow-list
    vui_endpoints._rpc = _mock_agents_rpc
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/agents_rpc/rpc/kw_only', method='POST',
                           HTTP_AUTHORIZATION='BEARER foo')
    response = vui_endpoints.handle_platforms_agents_rpc_method(env, {'foo': 1, 'bar': 2})
    body = json.loads(response.response[0])
    assert body == [1, 2]
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/agents_rpc/rpc/args_and_kw', method='POST',
                           HTTP_AUTHORIZATION='BEARER foo')
    response = vui_endpoints.handle_platforms_agents_rpc_method(env, {'args': [1, 2], 'foo': 3, 'bar': 4})
    body = json.loads(response.response[0])
    assert body == [1, 2, 3, 4]
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/agents_rpc/rpc/args_only', method='POST',
                           HTTP_AUTHORIZATION='BEARER foo')
    response = vui_endpoints.handle_platforms_agents_rpc_method(env, [1, 2])
    body = json.loads(response.response[0])
    assert body == [1, 2]


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], ['PUT', 'DELETE']))
def test_handle_platforms_agents_running_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/running', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_running(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', {'running': True}),
    ('stopped1', {'running': False}),
    ('not_exist', {'error': 'Agent "not_exist" not found.'})])
def test_handle_platforms_agents_running_get_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/running'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_running(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize('vip_identity, uuid, restart, status_code', [
    ('run1', '1', False, '400'),
    ('run1', '1', True, '204'),
    ('run1', '1', 'foo', '400'),
    ('stopped2', '4', False, '204'),
    ('stopped1', '3', True, '204'),
    ('not_exist', '', True, '400')
])
def test_handle_platforms_agents_running_put_response(mock_platform_web_service, vip_identity, uuid,
                                                      restart, status_code):
    query_string = f'restart={restart}'
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/running'
    env = get_test_web_env(path, method='PUT', query_string=query_string, HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_running(env, {})
    check_response_codes(response, status_code)
    if status_code == '204':
        if restart:
            vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', vip_identity,
                                                           external_platform='my_instance_name'),
                                                 mock.call(CONTROL, 'restart_agent', uuid,
                                                           external_platform='my_instance_name')])
        else:
            vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', vip_identity,
                                                           external_platform='my_instance_name'),
                                                mock.call(CONTROL, 'peerlist', external_platform='my_instance_name'),
                                                mock.call(CONTROL, 'start_agent', uuid,
                                                          external_platform='my_instance_name')])


@pytest.mark.parametrize('vip_identity, uuid, status_code', [
    ('run1', '1', '204'),
    ('stopped1', '3', '204'),
    ('not_exist', '', '400')
])
def test_handle_platforms_agents_running_delete_response(mock_platform_web_service, vip_identity, uuid, status_code):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/running'
    env = get_test_web_env(path, method='DELETE', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_running(env, {})
    check_response_codes(response, status_code)
    if status_code == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', vip_identity,
                                                       external_platform='my_instance_name'),
                                             mock.call(CONTROL, 'stop_agent', uuid,
                                                       external_platform='my_instance_name')])


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], []))
def test_handle_platforms_agents_status_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/status', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_status(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', {'name': 'rn1', 'uuid': '1', 'tag': 'r1', 'priority': None, 'running': True,
              'enabled': False, 'pid': 10, 'exit_code': None}),
    ('run2', {'name': 'rn2', 'uuid': '2', 'tag': 'r2', 'priority': 50, 'running': True,
              'enabled': True, 'pid': 11, 'exit_code': None}),
    ('stopped1', {'name': 'stp1', 'uuid': '3', 'tag': 'st1', 'priority': None, 'running': False,
                  'enabled': False, 'pid': None, 'exit_code': None}),
    ('stopped2', {'name': 'stp2', 'uuid': '4', 'tag': 'st2', 'priority': 35, 'running': False,
                  'enabled': True, 'pid': 12, 'exit_code': 0}),
    ('not_exist', {'error': 'Agent "not_exist" not found.'})])
def test_handle_platforms_agents_status_get_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/status'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_status(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], [ 'PUT', 'DELETE']))
def test_handle_platforms_agents_tag_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/run1/tag', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_tag(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', {'tag': 'r1'}),
    ('run2', {'tag': 'r2'}),
    ('stopped1', {'tag': 'st1'}),
    ('stopped2', {'tag': 'st2'}),
    ('not_exist', {'error': "Agent 'not_exist' not found."})])
def test_handle_platforms_agents_tag_get_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/tag'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_agents_tag(env, {})
    assert json.loads(response.response[0]) == expected


@pytest.mark.parametrize('vip_identity, uuid, tag, expected', [
    ('run1', '1', 'foo', '204'),
    ('not_exists', None, 'foo', '400')
])
def test_handle_platforms_agents_tag_put_response(mock_platform_web_service, vip_identity, uuid, tag, expected):
    data = {"tag": tag}
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/tag'
    env = get_test_web_env(path, method='PUT', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_tag(env, data)
    check_response_codes(response, expected)
    if expected == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', vip_identity,
                                                       external_platform='my_instance_name'),
                                             mock.call(CONTROL, 'tag_agent', uuid, tag,
                                                       external_platform='my_instance_name')])
    elif expected == '400':
        assert json.loads(response.response[0]) == {'error': "Agent 'not_exists' not found."}


@pytest.mark.parametrize('vip_identity, expected', [
    ('run1', '204'),
    ('not_exists', '400')
])
def test_handle_platforms_agents_tag_delete_response(mock_platform_web_service, vip_identity, expected):
    path = f'/vui/platforms/my_instance_name/agents/{vip_identity}/tag'
    env = get_test_web_env(path, method='DELETE', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_agents_tag(env, {})
    check_response_codes(response, expected)
    if expected == '204':
        vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'identity_exists', vip_identity,
                                                       external_platform='my_instance_name'),
                                             mock.call(CONTROL, 'tag_agent', '1', None,
                                                       external_platform='my_instance_name')])
    elif expected == '400':
        assert json.loads(response.response[0]) == {'error': "Agent 'not_exists' not found."}


def _mock_devices_rpc(peer, meth, *args, external_platform=None, **kwargs):
    # The driver's get/set/revert take topic=[<identifier>, ...] and key results by those identifiers.
    if peer == PLATFORM_DRIVER and meth == 'get':
        assert all(t.startswith('devices/') for t in kwargs['topic'])
        return [{t: 10.0 for t in kwargs['topic']}, {}]
    elif peer == PLATFORM_DRIVER and meth == 'set':
        assert all(t.startswith('devices/') for t in kwargs['topic'])
        return [{t: kwargs['value'] for t in kwargs['topic']}, {}]
    elif peer == PLATFORM_DRIVER and meth == 'revert':
        assert all(t.startswith('devices/') for t in kwargs['topic'])
        return {}
    elif peer == 'platform.tagging' and meth == 'get_topics_by_tag':
        return []


@pytest.mark.parametrize("method, status", gen_response_codes(['GET', 'PUT', 'DELETE']))
def test_handle_platforms_devices_status_code(mock_platform_web_service, method, status):
    with mock.patch('volttron.services.web.vui_endpoints.DeviceTree.from_store', return_value=_build_device_tree()):
        env = get_test_web_env('/vui/platforms/my_instance_name/devices/Campus/Building1/Fake1/SampleWritableFloat1',
                               method=method, HTTP_AUTHORIZATION='BEARER foo')
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        vui_endpoints._rpc = _mock_devices_rpc
        response = vui_endpoints.handle_platforms_devices(env, {'value': 1})
        check_response_codes(response, status)


DEVICE_TOPIC_LIST = ['Campus/Building1/Fake1/SampleWritableFloat1', 'Campus/Building1/Fake1/SampleBool1',
                     'Campus/Building2/Fake1/SampleWritableFloat1', 'Campus/Building2/Fake1/SampleBool1',
                     'Campus/Building3/Fake1/SampleWritableFloat1', 'Campus/Building3/Fake1/SampleBool1']


# TODO: Test with tag query parameters.
@pytest.mark.parametrize('topic, is_point, read_all, return_routes, return_writability, return_values, return_config', [
    ('', False, False, True, True, True, False),
    ('', False, True, True, True, True, False),
    ('Campus/Building1/Fake1', False, False, True, True, True, False),
    ('Campus/Building1/Fake1', False, True, True, True, True, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, False, True, True, True, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, True, False, False, False, True)
])
def test_handle_platforms_devices_get_response(mock_platform_web_service, topic, is_point, read_all, return_routes,
                                               return_writability, return_values, return_config):
    query_string = f'read-all={read_all}&routes={return_routes}&writability={return_writability}' \
                   f'&values={return_values}&config={return_config}'
    with mock.patch('volttron.services.web.vui_endpoints.DeviceTree.from_store', return_value=_build_device_tree()):
        env = get_test_web_env(f'/vui/platforms/my_instance_name/devices/{topic}', query_string=query_string,
                               method='GET', HTTP_AUTHORIZATION='BEARER foo')
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        vui_endpoints._rpc = _mock_devices_rpc
        response = vui_endpoints.handle_platforms_devices(env, {})
        if not read_all and not is_point:
            seg_number = 0 if topic == '' else len(topic.split('/'))
            _log.debug(f'SEG_NUMBER is: {seg_number}')
            keys = [list_topic.split('/')[seg_number] for list_topic in DEVICE_TOPIC_LIST]
            check_links_return(response, list(set(keys)))
        else:
            body = json.loads(response.response[0])
            assert isinstance(body, dict)
            for k, v in body.items():
                keys = list(v.keys())
                assert isinstance(v, dict)
                assert 'route' in keys if return_routes else 'route' not in keys
                if return_writability:
                    assert 'writable' in keys
                    assert isinstance(v['writable'], bool)
                else:
                    assert 'writable' not in keys
                assert 'value' in keys if return_values else 'value' not in keys
                assert 'config' in keys if return_config else 'config' not in keys


@pytest.mark.parametrize('topic, is_point, write_all, confirm_values', [
    ('', False, False, False),
    ('', False, True, False),
    ('Campus/Building1/Fake1/', False, False, False),
    ('Campus/Building1/Fake1/', False, True, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, False, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, True, True)
])
def test_handle_platforms_devices_put_response(mock_platform_web_service, topic, is_point, write_all, confirm_values):
    query_string = f'write-all={write_all}&confirm-values={confirm_values}'
    with mock.patch('volttron.services.web.vui_endpoints.DeviceTree.from_store', return_value=_build_device_tree()):
        env = get_test_web_env(f'/vui/platforms/my_instance_name/devices/{topic}', query_string=query_string,
                               method='PUT', HTTP_AUTHORIZATION='BEARER foo')
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        vui_endpoints._rpc = _mock_devices_rpc
        response = vui_endpoints.handle_platforms_devices(env, {})
        body = json.loads(response.response[0])
        _log.debug('BODY IS:')
        _log.debug(body)
        assert isinstance(body, dict)
        if not is_point and not write_all:
            assert body['error'] == "Use of wildcard expressions, regex, or tags may set multiple points." \
                                    " Query must include 'write-all=true'."
        else:
            for k, v in body.items():
                keys = list(v.keys())
                assert 'route' in keys
                assert 'set_error' in keys
                assert 'writable' in keys
                assert isinstance(v['writable'], bool)
                if confirm_values:
                    assert 'value' in keys
                    assert "value_check_error" in keys
                else:
                    assert 'value' not in keys
                    assert "value_check_error" not in keys


@pytest.mark.parametrize('topic, is_point, write_all, confirm_values', [
    ('', False, False, False),
    ('', False, True, False),
    ('Campus/Building1/Fake1/', False, False, False),
    ('Campus/Building1/Fake1/', False, True, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, False, False),
    ('Campus/Building1/Fake1/SampleWritableFloat1', True, True, True)
])
def test_handle_platforms_devices_delete_response(mock_platform_web_service, topic, is_point, write_all,
                                                  confirm_values):
    query_string = f'write-all={write_all}&confirm-values={confirm_values}'
    with mock.patch('volttron.services.web.vui_endpoints.DeviceTree.from_store', return_value=_build_device_tree()):
        env = get_test_web_env(f'/vui/platforms/my_instance_name/devices/{topic}', query_string=query_string,
                               method='DELETE', HTTP_AUTHORIZATION='BEARER foo')
        vui_endpoints = VUIEndpoints(mock_platform_web_service)
        vui_endpoints._rpc = _mock_devices_rpc
        response = vui_endpoints.handle_platforms_devices(env, {})
        body = json.loads(response.response[0])
        _log.debug('BODY IS:')
        _log.debug(body)
        assert isinstance(body, dict)
        if not is_point and not write_all:
            assert body['error'] == "Use of wildcard expressions, regex, or tags may set multiple points." \
                                    " Query must include 'write-all=true'."
        else:
            for k, v in body.items():
                keys = list(v.keys())
                assert 'route' in keys
                assert 'revert_error' in keys
                assert 'writable' in keys
                assert isinstance(v['writable'], bool)
                if confirm_values:
                    assert 'value' in keys
                    assert "value_check_error" in keys
                else:
                    assert 'value' not in keys
                    assert "value_check_error" not in keys


def test_handle_platforms_pubsub(mock_platform_web_service):
    pass
# TODO: handle_platforms_pubsub


HISTORIAN_TOPIC_LIST = ['Campus/Building1/Fake1/SampleBool1', 'Campus/Building1/Fake1/EKG',
                        'Campus/Building1/Fake1/SampleWritableFloat1', 'Campus/Building1/Fake1/EKG_Sin',
                        'Campus/Building1/Fake1/EKG_Cos']


def _mock_historians_rpc(peer, meth, *args, external_platform=None, **kwargs):
    if meth == 'get_topic_list':
        return HISTORIAN_TOPIC_LIST
    elif meth == 'query':
        if len(args[0]) > 1:
            retval = {'values': {}, 'metadata': {}}
            for topic in args[0]:
                retval['values'][topic] = [['2021-06-17T22:15:00.551451+00:00', True],
                                   ['2021-06-17T22:16:00.550595+00:00', True],
                                   ['2021-06-17T22:17:00.551621+00:00', True],
                                   ['2021-06-17T22:18:00.551112+00:00', True],
                                   ['2021-06-17T22:19:00.551337+00:00', True]]
        else:
            retval = {'values': [['2021-06-17T22:15:00.551451+00:00', True]],
                      'metadata': {'units': 'On / Off', 'type': 'integer', 'tz': 'US/Pacific'}}
        return retval


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_historians_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/historians', method=method, HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_historians(env, {})
    check_response_codes(response, status)


def test_handle_platforms_historians_response(mock_platform_web_service):
    path = f'/vui/platforms/my_instance_name/historians'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._get_agents = lambda x: ['platform.other', 'foo.historian', 'random.agent', 'platform.historian']
    response = vui_endpoints.handle_platforms_historians(env, {})
    check_links_return(response, ['platform.historian', 'foo.historian'], leading_path=path)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_historians_historian_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/historians/my_instance_name', method=method,
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    response = vui_endpoints.handle_platforms_historians_historian(env, {})
    check_response_codes(response, status)


def test_handle_platforms_historians_historian_response(mock_platform_web_service):
    path = f'/vui/platforms/my_instance_name/historians/platform.historian'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    response = vui_endpoints.handle_platforms_historians_historian(env, {})
    check_links_return(response, ['topics'], leading_path=path)


@pytest.mark.parametrize("method, status", gen_response_codes(['GET']))
def test_handle_platforms_historians_historian_topics_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/historians/my_instance_name/topics', method=method,
                           HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_historians_rpc
    response = vui_endpoints.handle_platforms_historians_historian_topics(env, {})
    check_response_codes(response, status)


# Test tag query parameters.
@pytest.mark.parametrize('topic, is_full_topic, read_all, return_routes, return_values', [
    ('', False, False, True, True),
    ('', False, True, True, True),
    ('Campus/Building1/Fake1', False, False, True, True),
    ('Campus/Building1/Fake1', False, True, True, True),
    ('Campus/Building1/Fake1/SampleBool1', True, False, True, True),
    ('Campus/Building1/Fake1/SampleBool1', True, False, False, False)
])
def test_handle_platforms_historians_historian_topics_get_response(mock_platform_web_service, topic, is_full_topic,
                                                                   read_all, return_routes, return_values):
    query_string = f'read-all={read_all}&routes={return_routes}&values={return_values}'
    env = get_test_web_env(f'/vui/platforms/my_instance_name/historians/platform.historian/topics/{topic}',
                           query_string=query_string, method='GET', HTTP_AUTHORIZATION='BEARER foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_historians_rpc
    response = vui_endpoints.handle_platforms_historians_historian_topics(env, {})
    if not read_all and not is_full_topic:
        seg_number = 0 if topic == '' else len(topic.split('/'))
        keys = [list_topic.split('/')[seg_number] for list_topic in HISTORIAN_TOPIC_LIST]
        _log.debug(f'KEYS IS: {keys}')
        check_links_return(response, list(set(keys)))
    else:
        body = json.loads(response.response[0])
        assert isinstance(body, dict)
        _log.debug('BODY IS:')
        _log.debug(body)
        for k, v in body.items():
            keys = v.keys()
            assert 'route' in keys if return_routes else 'route' not in keys
            assert 'value' in keys if return_values else 'value' not in keys


@pytest.mark.parametrize("method, status", gen_response_codes(['GET'], ['DELETE']))
def test_handle_platforms_status_status_code(mock_platform_web_service, method, status):
    env = get_test_web_env('/vui/platforms/my_instance_name/status', method=method,
                           HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_status(env, {})
    check_response_codes(response, status)


@pytest.mark.parametrize('expected', [{
    'run1': {'name': 'rn1', 'uuid': '1', 'tag': 'r1', 'priority': None, 'running': True,
             'enabled': False, 'pid': 10, 'exit_code': None},
    'run2': {'name': 'rn2', 'uuid': '2', 'tag': 'r2', 'priority': 50, 'running': True,
             'enabled': True, 'pid': 11, 'exit_code': None},
    'stopped1': {'name': 'stp1', 'uuid': '3', 'tag': 'st1', 'priority': None,  'running': False,
                 'enabled': False, 'pid': None, 'exit_code': None},
    'stopped2': {'name': 'stp2', 'uuid': '4', 'tag': 'st2', 'priority': 35, 'running': False,
                 'enabled': True, 'pid': 12, 'exit_code': 0}}])
def test_handle_platforms_status_get_response(mock_platform_web_service, expected):
    path = f'/vui/platforms/my_instance_name/status'
    env = get_test_web_env(path, method='GET', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = _mock_agents_rpc
    response = vui_endpoints.handle_platforms_status(env, {})
    assert json.loads(response.response[0]) == expected


def test_handle_platforms_status_delete_response(mock_platform_web_service):
    path = f'/vui/platforms/my_instance_name/status'
    env = get_test_web_env(path, method='DELETE', HTTP_AUTHORIZATION='Bearer foo')
    vui_endpoints = VUIEndpoints(mock_platform_web_service)
    vui_endpoints._rpc = MagicMock(wraps=_mock_agents_rpc)
    response = vui_endpoints.handle_platforms_status(env, {})
    check_response_codes(response, '204')
    vui_endpoints._rpc.assert_has_calls([mock.call(CONTROL, 'clear_status', True,
                                                   external_platform='my_instance_name')])


# ---------------------------------------------------------------------------- agent selection ('-' wildcard)

def _vui_with_agents(mock_platform_web_service):
    vui = VUIEndpoints(mock_platform_web_service)
    vui._rpc = MagicMock(wraps=_mock_agents_rpc)
    return vui


def _call(vui, handler, path, method='GET', query=''):
    env = get_test_web_env(path, method=method, query_string=query, HTTP_AUTHORIZATION='Bearer foo')
    response = getattr(vui, handler)(env, {})
    return response.status_code, json.loads(response.get_data(as_text=True))


P = '/vui/platforms/my_instance_name'
EXT = {'external_platform': 'my_instance_name'}


@pytest.mark.parametrize('query, expected', [
    ('', {'run1', 'run2', 'stopped1', 'stopped2'}),                       # every installed agent
    ('tag=*', {'run1', 'run2', 'stopped1', 'stopped2'}),                  # every tagged agent (all have tags here)
    ('tag=r*', {'run1', 'run2'}),
    ('tag=st2', {'stopped2'}),
    ('regex=^stopped', {'stopped1', 'stopped2'}),
    ('tag=*&regex=1$', {'run1', 'stopped1'}),                            # parameters intersect
    ('tag=nomatch', set()),
    ('include-hidden=true&regex=^hid', {'hid1', 'hid2'}),
    ('regex=^hid', set()),                                                # hidden peers excluded by default
])
def test_running_selection_get(mock_platform_web_service, query, expected):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', query=query)
    assert code == 200
    assert set(body) == expected
    for identity, entry in body.items():
        assert entry == {'running': identity in ('run1', 'run2', 'hid1', 'hid2')}


def test_selection_invalid_regex_is_400(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', query='regex=(')
    assert code == 400 and 'Invalid regex' in body['error']


def test_selection_unknown_platform_is_400(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', '/vui/platforms/nope/agents/-/running', query='tag=*')
    assert code == 400 and 'Unknown platform' in body['error']


def test_running_selection_put_starts_only_stopped_agents(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', 'PUT', 'tag=*')
    assert code == 200 and set(body) == {'run1', 'run2', 'stopped1', 'stopped2'}
    started = {c.args[2] for c in vui._rpc.call_args_list if c.args[:2] == (CONTROL, 'start_agent')}
    assert started == {'3', '4'}                                           # the running agents are left alone
    assert all(entry['error'] is None for entry in body.values())


def test_running_selection_put_restart(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', 'PUT', 'tag=r1&restart=true')
    assert code == 200 and list(body) == ['run1']
    vui._rpc.assert_any_call(CONTROL, 'restart_agent', '1', **EXT)


def test_running_selection_delete_stops_only_running_agents(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', 'DELETE', 'tag=*')
    stopped = {c.args[2] for c in vui._rpc.call_args_list if c.args[:2] == (CONTROL, 'stop_agent')}
    assert code == 200 and stopped == {'1', '2'}


def test_running_selection_reports_per_agent_errors(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    # Hidden peers are not installed agents and cannot be started or stopped; the batch still completes.
    code, body = _call(vui, 'handle_platforms_agents_running', f'{P}/agents/-/running', 'DELETE',
                       'include-hidden=true&regex=^(hid1|run1)$')
    assert code == 200
    assert body['run1']['error'] is None
    assert 'not an installed agent' in body['hid1']['error']


def test_enabled_selection_get(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_enabled', f'{P}/agents/-/enabled', query='tag=*')
    assert code == 200
    assert body == {'run1': {'status': False, 'priority': None}, 'run2': {'status': True, 'priority': 50},
                    'stopped1': {'status': False, 'priority': None}, 'stopped2': {'status': True, 'priority': 35}}


def test_enabled_selection_put_and_delete(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_enabled', f'{P}/agents/-/enabled', 'PUT', 'tag=st*&priority=10')
    assert code == 200
    assert body == {'stopped1': {'status': True, 'priority': 10, 'error': None},
                    'stopped2': {'status': True, 'priority': 10, 'error': None}}
    vui._rpc.assert_any_call(CONTROL, 'prioritize_agent', '3', '10', **EXT)
    vui._rpc.assert_any_call(CONTROL, 'prioritize_agent', '4', '10', **EXT)
    code, body = _call(vui, 'handle_platforms_agents_enabled', f'{P}/agents/-/enabled', 'DELETE', 'tag=r2')
    assert code == 200 and body == {'run2': {'status': False, 'priority': None, 'error': None}}
    vui._rpc.assert_any_call(CONTROL, 'prioritize_agent', '2', None, **EXT)


def test_enabled_selection_put_rejects_bad_priority(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_enabled', f'{P}/agents/-/enabled', 'PUT', 'tag=*&priority=100')
    assert code == 400 and 'Priority' in body['error']
    assert not [c for c in vui._rpc.call_args_list if c.args[:2] == (CONTROL, 'prioritize_agent')]


def test_status_selection_get(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_status', f'{P}/agents/-/status', query='tag=r*')
    assert code == 200 and set(body) == {'run1', 'run2'}
    assert body['run1']['running'] is True and body['run1']['pid'] == 10


@pytest.mark.parametrize('identity, code, keys', [
    ('run1', 200, {'peer', 'service_agent', 'connected', 'last_heartbeat', 'message'}),
    ('stopped1', 400, {'error'}),                                          # not connected: no health entry
])
def test_agent_health(mock_platform_web_service, identity, code, keys):
    vui = _vui_with_agents(mock_platform_web_service)
    got, body = _call(vui, 'handle_platforms_agents_health', f'{P}/agents/{identity}/health')
    assert got == code and set(body) == keys


def test_agent_health_selection(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_health', f'{P}/agents/-/health', query='tag=*')
    assert code == 200 and set(body) == {'run1', 'run2'}                 # stopped agents have no health entry
    code, body = _call(vui, 'handle_platforms_agents_health', f'{P}/agents/-/health',
                       query='include-hidden=true&regex=^hid')
    assert code == 200 and set(body) == {'hid1', 'hid2'}


def test_platform_health(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_health', f'{P}/health')
    assert code == 200 and set(body) == {'run1', 'run2', 'hid1', 'hid2'}
    code, body = _call(vui, 'handle_platforms_health', '/vui/platforms/nope/health')
    assert code == 400


def test_agents_list_tag_and_regex_filters(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents', f'{P}/agents', query='tag=r*')
    assert code == 200 and set(body['links']) == {'run1', 'run2'}
    code, body = _call(vui, 'handle_platforms_agents', f'{P}/agents', query='agent-state=installed&tag=*')
    assert set(body['links']) == {'run1', 'run2', 'stopped1', 'stopped2'}
    code, body = _call(vui, 'handle_platforms_agents', f'{P}/agents', query='agent-state=installed&regex=^stopped')
    assert set(body['links']) == {'stopped1', 'stopped2'}
    code, body = _call(vui, 'handle_platforms_agents', f'{P}/agents', query='regex=(')
    assert code == 400


def test_wildcard_agent_links_only_selection_routes(mock_platform_web_service):
    vui = _vui_with_agents(mock_platform_web_service)
    code, body = _call(vui, 'handle_platforms_agents_agent', f'{P}/agents/-')
    assert code == 200 and set(body['links']) == {'running', 'enabled', 'status', 'health'}
