"""Exercise every HTTP route of the web service against a live platform.

Routes covered: static files and redirects, /admin pages, /authenticate (POST/PUT/DELETE), and every /vui route
registered by VUIEndpoints.get_routes(), including the pubsub websocket.
"""
import json
import time

import pytest
import requests
import websocket

from conftest import CONTROL, DEVICE_TOPIC, LISTENER, PASSWORD, PLATFORM_DRIVER, USERNAME, wait_until

POINT = f'{DEVICE_TOPIC}/SampleWritableFloat1'
READ_ONLY_POINT = f'{DEVICE_TOPIC}/OutsideAirTemperature1'


# ---------------------------------------------------------------------------- static files and admin pages

class TestStaticAndAdmin:
    def test_root_redirects_to_index(self, api):
        r = api.get('/', allow_redirects=False)
        assert r.status_code == 302
        assert r.headers['Location'] == '/index.html'

    def test_index_page_is_served(self, api):
        r = api.get('/index.html')
        assert r.status_code == 200
        assert 'text/html' in r.headers['Content-Type']
        assert '<html' in r.text.lower()

    def test_static_asset_has_nosniff_header(self, api):
        r = api.get('/index.html')
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_missing_static_file_is_404(self, api):
        assert api.get('/does-not-exist.html').status_code == 404

    def test_dotfile_is_404(self, api):
        assert api.get('/.hidden').status_code == 404

    def test_admin_root_serves_login_page(self, base_url):
        r = requests.get(f'{base_url}/admin/', timeout=10)
        assert r.status_code == 200
        assert 'password' in r.text.lower()

    def test_admin_login_html_served_without_token(self, base_url):
        r = requests.get(f'{base_url}/admin/login.html', timeout=10)
        assert r.status_code == 200

    def test_admin_page_without_token_is_401(self, base_url):
        r = requests.get(f'{base_url}/admin/index.html', timeout=10)
        assert r.status_code == 401

    def test_admin_page_with_bearer_header(self, api):
        r = api.get('/admin/index.html')
        assert r.status_code == 200
        assert 'text/html' in r.headers['Content-Type']

    def test_admin_page_with_bearer_cookie(self, base_url, tokens):
        r = requests.get(f'{base_url}/admin/index.html', cookies={'Bearer': tokens['access_token']}, timeout=10)
        assert r.status_code == 200

    def test_admin_page_with_garbage_token_is_401(self, base_url):
        r = requests.get(f'{base_url}/admin/index.html', headers={'Authorization': 'Bearer nope'}, timeout=10)
        assert r.status_code == 401

    def test_admin_unknown_page_is_404(self, api):
        assert api.get('/admin/pending_auth_reqs.html').status_code == 404

    def test_admin_credential_api_is_gone(self, api):
        r = api.get('/admin/api/certs')
        assert r.status_code in (200, 404)
        assert 'application/json' not in r.headers.get('Content-Type', '')


# ---------------------------------------------------------------------------- /authenticate

class TestAuthenticate:
    def test_login_returns_both_tokens(self, tokens):
        assert set(tokens) == {'access_token', 'refresh_token'}

    def test_wrong_password_is_401(self, base_url):
        r = requests.post(f'{base_url}/authenticate', json={'username': USERNAME, 'password': 'wrong'}, timeout=10)
        assert r.status_code == 401
        assert r.json() == {'error': 'Not Authorized'}

    def test_unknown_user_is_401_with_same_body(self, base_url):
        r = requests.post(f'{base_url}/authenticate', json={'username': 'nobody', 'password': PASSWORD}, timeout=10)
        assert r.status_code == 401
        assert r.json() == {'error': 'Not Authorized'}

    def test_missing_fields_is_401(self, base_url):
        r = requests.post(f'{base_url}/authenticate', json={'username': USERNAME}, timeout=10)
        assert r.status_code == 401

    def test_refresh_token_renews_access_token(self, base_url, tokens, P):
        r = requests.put(f'{base_url}/authenticate', json={},
                         headers={'Authorization': f"Bearer {tokens['refresh_token']}"}, timeout=10)
        assert r.status_code == 200, r.text
        new_token = r.json()['access_token']
        r = requests.get(f'{base_url}{P}', headers={'Authorization': f'Bearer {new_token}'}, timeout=10)
        assert r.status_code == 200

    def test_access_token_cannot_renew(self, base_url, tokens):
        r = requests.put(f'{base_url}/authenticate', json={},
                         headers={'Authorization': f"Bearer {tokens['access_token']}"}, timeout=10)
        assert r.status_code == 401

    def test_renew_without_token_is_401(self, base_url):
        assert requests.put(f'{base_url}/authenticate', json={}, timeout=10).status_code == 401

    def test_revoke_is_not_implemented(self, api):
        assert api.delete('/authenticate').status_code == 501

    def test_get_is_405(self, api):
        assert api.get('/authenticate').status_code == 405


# ---------------------------------------------------------------------------- VUI authorization

class TestVuiAuthorization:
    def test_no_token_is_401(self, base_url):
        r = requests.get(f'{base_url}/vui', timeout=10)
        assert r.status_code == 401
        assert r.json() == {'error': 'Not Authorized'}

    def test_garbage_token_is_401(self, base_url):
        r = requests.get(f'{base_url}/vui', headers={'Authorization': 'Bearer nope'}, timeout=10)
        assert r.status_code == 401

    def test_malformed_header_is_401(self, base_url):
        r = requests.get(f'{base_url}/vui', headers={'Authorization': 'Basic abc'}, timeout=10)
        assert r.status_code == 401

    def test_refresh_token_is_not_accepted_for_api(self, base_url, tokens):
        r = requests.get(f'{base_url}/vui', headers={'Authorization': f"Bearer {tokens['refresh_token']}"}, timeout=10)
        assert r.status_code == 403

    def test_user_without_vui_group_is_403(self, platform, base_url):
        platform.add_web_user('plain', 'plain-user-password', groups=['admin'])
        r = requests.post(f'{base_url}/authenticate', json={'username': 'plain', 'password': 'plain-user-password'},
                          timeout=10)
        assert r.status_code == 200, r.text
        token = r.json()['access_token']
        assert requests.get(f'{base_url}/vui', headers={'Authorization': f'Bearer {token}'}, timeout=10).status_code == 403
        assert requests.get(f'{base_url}/admin/index.html', headers={'Authorization': f'Bearer {token}'},
                            timeout=10).status_code == 200


# ---------------------------------------------------------------------------- /vui and /vui/platforms

class TestRootAndPlatforms:
    def test_vui_root_links(self, api):
        r = api.get('/vui')
        assert r.status_code == 200
        assert r.json() == {'links': {'platforms': '/vui/platforms'}}

    def test_platforms_lists_local_platform(self, api, platform_name):
        r = api.get('/vui/platforms')
        assert r.status_code == 200
        assert r.json()['links'] == {platform_name: f'/vui/platforms/{platform_name}'}

    def test_platform_links(self, api, P):
        r = api.get(P)
        assert r.status_code == 200
        links = r.json()['links']
        for key in ('agents', 'devices', 'historians', 'logs', 'pubsub', 'status', 'packaged-configs'):
            assert key in links, links
            assert links[key] == f'{P}/{key}'

    def test_unknown_platform_is_400(self, api):
        r = api.get('/vui/platforms/not-a-platform')
        assert r.status_code == 400
        assert 'Unknown platform' in r.json()['error']

    def test_unsupported_method_is_501(self, api):
        r = api.post('/vui/platforms', json={})
        assert r.status_code == 501


# ---------------------------------------------------------------------------- /agents

class TestAgents:
    def test_running_agents(self, api, P):
        r = api.get(f'{P}/agents')
        assert r.status_code == 200
        links = r.json()['links']
        assert PLATFORM_DRIVER in links and LISTENER in links
        assert links[PLATFORM_DRIVER] == f'{P}/agents/{PLATFORM_DRIVER}'

    def test_installed_agents(self, api, P):
        r = api.get(f'{P}/agents', params={'agent-state': 'installed'})
        assert r.status_code == 200
        assert {PLATFORM_DRIVER, LISTENER} <= set(r.json()['links'])

    def test_include_hidden_adds_platform_services(self, api, P):
        r = api.get(f'{P}/agents', params={'include-hidden': 'true'})
        assert r.status_code == 200
        assert CONTROL in r.json()['links']

    def test_bad_agent_state_is_400(self, api, P):
        assert api.get(f'{P}/agents', params={'agent-state': 'bogus'}).status_code == 400

    def test_unknown_platform_is_400(self, api):
        assert api.get('/vui/platforms/nope/agents').status_code == 400

    def test_agent_links(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}')
        assert r.status_code == 200
        links = r.json()['links']
        for key in ('configs', 'enabled', 'running', 'status', 'tag'):
            assert key in links, links
        assert 'rpc' in links

    def test_agent_status(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/status')
        assert r.status_code == 200
        body = r.json()
        assert body['running'] is True
        assert body['pid'] and body['exit_code'] is None

    def test_unknown_agent_status_is_400(self, api, P):
        assert api.get(f'{P}/agents/nobody/status').status_code == 400

    def test_tag_lifecycle(self, api, P):
        url = f'{P}/agents/{LISTENER}/tag'
        assert api.get(url).json() == {'tag': 'listener'}
        assert api.put(url, json={'tag': 'renamed'}).status_code == 204
        assert api.get(url).json() == {'tag': 'renamed'}
        assert api.delete(url).status_code == 204
        assert api.get(url).json() == {'tag': 'None'}
        assert api.put(url, json={'tag': 'listener'}).status_code == 204

    def test_tag_of_unknown_agent(self, api, P):
        assert api.get(f'{P}/agents/nobody/tag').status_code == 400
        assert api.put(f'{P}/agents/nobody/tag', json={'tag': 'x'}).status_code == 400

    def test_enabled_lifecycle(self, api, P):
        url = f'{P}/agents/{LISTENER}/enabled'
        assert api.get(url).json() == {'status': False, 'priority': None}
        assert api.put(url, params={'priority': '60'}).status_code == 204
        assert api.get(url).json() == {'status': True, 'priority': 60}
        assert api.delete(url).status_code == 204
        assert api.get(url).json() == {'status': False, 'priority': None}

    def test_enabled_rejects_bad_priority(self, api, P):
        assert api.put(f'{P}/agents/{LISTENER}/enabled', params={'priority': 'abc'}).status_code == 400
        assert api.put(f'{P}/agents/{LISTENER}/enabled', params={'priority': '100'}).status_code == 400

    def test_running_lifecycle(self, api, P):
        url = f'{P}/agents/{LISTENER}/running'
        assert api.get(url).json() == {'running': True}
        assert api.put(url).status_code == 400          # already running
        assert api.delete(url).status_code == 204
        wait_until(lambda: api.get(url).json()['running'] is False, message='listener did not stop')
        assert api.put(url).status_code == 204
        wait_until(lambda: api.get(url).json()['running'] is True, message='listener did not start')
        assert api.put(url, params={'restart': 'true'}).status_code == 204
        wait_until(lambda: api.get(url).json()['running'] is True, message='listener did not restart')

    def test_running_unknown_agent_is_400(self, api, P):
        assert api.get(f'{P}/agents/nobody/running').status_code == 400


# ---------------------------------------------------------------------------- /agents/:id/configs

class TestAgentConfigs:
    def test_list_configs(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs')
        assert r.status_code == 200
        links = r.json()['links']
        assert f'devices/{DEVICE_TOPIC}' in links
        assert links[f'devices/{DEVICE_TOPIC}'] == f'{P}/agents/{PLATFORM_DRIVER}/configs/devices/{DEVICE_TOPIC}'

    def test_list_stores(self, api, P):
        r = api.get(f'{P}/agents/-/configs')
        assert r.status_code == 200
        assert PLATFORM_DRIVER in r.json()

    def test_get_json_config(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/devices/{DEVICE_TOPIC}')
        assert r.status_code == 200
        assert r.json()['driver_type'] == 'fake'

    def test_get_csv_config(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/registry_configs/fake.csv')
        assert r.status_code == 200
        rows = r.json()
        assert isinstance(rows, list) and any(row['Volttron Point Name'] == 'SampleWritableFloat1' for row in rows)

    def test_get_csv_config_as_csv(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/registry_configs/fake.csv', headers={'Accept': 'text/csv'})
        assert r.status_code == 200, r.text
        assert r.headers['Content-Type'].startswith('text/csv')
        assert r.text.startswith('Point Name,Volttron Point Name')

    def test_get_json_config_as_text(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/devices/{DEVICE_TOPIC}', headers={'Accept': 'text/plain'})
        assert r.status_code == 200, r.text
        assert r.headers['Content-Type'].startswith('text/plain')
        assert json.loads(r.text)['driver_type'] == 'fake'

    def test_get_json_config_as_csv_is_406(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/devices/{DEVICE_TOPIC}', headers={'Accept': 'text/csv'})
        assert r.status_code == 406, r.text

    def test_get_config_unacceptable_type_is_406(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/devices/{DEVICE_TOPIC}',
                    headers={'Accept': 'application/xml'})
        assert r.status_code == 406, r.text

    def test_get_missing_config_is_400(self, api, P):
        assert api.get(f'{P}/agents/{PLATFORM_DRIVER}/configs/does-not-exist').status_code == 400

    def test_config_crud(self, api, P):
        agent = 'e2e.config.agent'
        base = f'{P}/agents/{agent}/configs'
        r = api.post(base, params={'config-name': 'settings'}, json={'a': 1})
        assert r.status_code == 201, r.text
        assert r.headers['Location'].endswith(f'/agents/{agent}/configs/settings')
        assert api.get(f'{base}/settings').json() == {'a': 1}
        assert api.post(base, params={'config-name': 'settings'}, json={'a': 2}).status_code == 409
        assert api.put(f'{base}/settings', json={'a': 3}).status_code == 204
        assert api.get(f'{base}/settings').json() == {'a': 3}
        r = api.put(f'{base}/notes', data='free text', headers={'Content-Type': 'text/plain'})
        assert r.status_code == 204
        assert api.get(f'{base}/notes').json() == 'free text'
        assert set(api.get(base).json()['links']) == {'settings', 'notes'}
        assert api.delete(f'{base}/settings').status_code == 204
        assert api.get(f'{base}/settings').status_code == 400
        assert api.delete(base).status_code == 204
        assert agent not in api.get(f'{P}/agents/-/configs').json()

    def test_config_rejects_unknown_content_type(self, api, P):
        r = api.put(f'{P}/agents/e2e.config.agent/configs/x', data='<x/>', headers={'Content-Type': 'application/xml'})
        assert r.status_code == 400


# ---------------------------------------------------------------------------- /agents/:id/rpc

class TestRpcProxy:
    def test_denied_peer_is_403(self, api, P):
        r = api.get(f'{P}/agents/{PLATFORM_DRIVER}/rpc')
        assert r.status_code == 403
        assert 'not permitted' in r.json()['error']

    def test_unlisted_peer_is_403(self, api, P):
        assert api.get(f'{P}/agents/config.store/rpc').status_code == 403
        assert api.get(f'{P}/agents/some.random.agent/rpc').status_code == 403

    def test_method_list_is_filtered_by_allow_list(self, api, P):
        r = api.get(f'{P}/agents/{CONTROL}/rpc')
        assert r.status_code == 200
        links = r.json()['links']
        assert set(links) == {'peerlist', 'list_agents'}
        assert links['peerlist'] == f'{P}/agents/{CONTROL}/rpc/peerlist'

    def test_wildcard_peer_lists_methods(self, api, P):
        r = api.get(f'{P}/agents/{LISTENER}/rpc')
        assert r.status_code == 200
        assert isinstance(r.json()['links'], dict)

    def test_method_inspect(self, api, P):
        r = api.get(f'{P}/agents/{CONTROL}/rpc/peerlist')
        assert r.status_code == 200
        assert 'params' in r.json() or 'doc' in r.json() or 'return' in r.json()

    def test_call_allowed_method(self, api, P):
        r = api.post(f'{P}/agents/{CONTROL}/rpc/peerlist', json=[])
        assert r.status_code == 200
        assert PLATFORM_DRIVER in r.json()

    def test_call_with_kwargs(self, api, P):
        r = api.post(f'{P}/agents/{CONTROL}/rpc/list_agents', json={})
        assert r.status_code == 200
        assert any(a['identity'] == PLATFORM_DRIVER for a in r.json())

    def test_denied_method_on_allowed_peer_is_403(self, api, P):
        assert api.post(f'{P}/agents/{CONTROL}/rpc/shutdown', json=[]).status_code == 403
        assert api.get(f'{P}/agents/{CONTROL}/rpc/install_agent').status_code == 403

    def test_unlisted_method_on_allowed_peer_is_403(self, api, P):
        assert api.post(f'{P}/agents/{CONTROL}/rpc/status_agents', json=[]).status_code == 403

    def test_unknown_method_on_wildcard_peer_is_400(self, api, P):
        r = api.post(f'{P}/agents/{LISTENER}/rpc/no_such_method', json=[])
        assert r.status_code == 400


# ---------------------------------------------------------------------------- /devices

class TestDevices:
    def test_devices_root_links(self, api, P):
        r = api.get(f'{P}/devices')
        assert r.status_code == 200, r.text
        assert r.json()['links'] == {'fake-campus': f'{P}/devices/fake-campus'}

    def test_intermediate_segment_links(self, api, P):
        r = api.get(f'{P}/devices/fake-campus/fake-building')
        assert r.status_code == 200, r.text
        assert r.json()['links'] == {'fake-device': f'{P}/devices/{DEVICE_TOPIC}'}

    def test_device_topic_lists_point_links(self, api, P):
        # A device topic without read-all is a partial topic: the response lists routes to its points.
        r = api.get(f'{P}/devices/{DEVICE_TOPIC}')
        assert r.status_code == 200, r.text
        assert r.json()['links']['SampleWritableFloat1'] == f'{P}/devices/{POINT}'

    def test_device_points(self, api, P):
        r = api.get(f'{P}/devices/{DEVICE_TOPIC}', params={'read-all': 'true'})
        assert r.status_code == 200, r.text
        points = r.json()
        assert POINT in points and READ_ONLY_POINT in points
        assert points[POINT]['route'] == f'{P}/devices/{POINT}'
        assert points[POINT]['writable'] is True
        assert points[READ_ONLY_POINT]['writable'] is False
        assert 'value' in points[POINT]

    def test_read_all_from_higher_segment(self, api, P):
        r = api.get(f'{P}/devices/fake-campus', params={'read-all': 'true'})
        assert r.status_code == 200, r.text
        assert POINT in r.json()

    def test_device_points_with_options(self, api, P):
        r = api.get(f'{P}/devices/{DEVICE_TOPIC}',
                    params={'read-all': 'true', 'values': 'false', 'routes': 'false', 'config': 'true'})
        assert r.status_code == 200, r.text
        entry = r.json()[POINT]
        assert 'value' not in entry and 'route' not in entry
        assert entry['writable'] is True and 'config' in entry

    def test_single_point_read(self, api, P):
        r = api.get(f'{P}/devices/{POINT}')
        assert r.status_code == 200, r.text
        assert r.json()[POINT]['value'] == 10.0

    def test_unknown_topic_is_400(self, api, P):
        r = api.get(f'{P}/devices/fake-campus/nope')
        assert r.status_code == 400
        assert 'not found' in r.json()['error']

    def test_write_and_revert_point(self, api, P):
        url = f'{P}/devices/{POINT}'
        r = api.put(url, params={'confirm-values': 'true'}, json={'value': 42})
        assert r.status_code == 200, r.text
        body = r.json()[POINT]
        assert body['set_error'] is None and body['value'] == 42.0
        assert api.get(url).json()[POINT]['value'] == 42.0
        r = api.delete(url, params={'confirm-values': 'true'})
        assert r.status_code == 200, r.text
        assert r.json()[POINT]['value'] == 10.0

    def test_write_read_only_point_is_405(self, api, P):
        r = api.put(f'{P}/devices/{READ_ONLY_POINT}', json={'value': 1})
        assert r.status_code == 405
        assert 'No selected points are writable' in r.text

    def test_multi_point_write_requires_write_all(self, api, P):
        r = api.put(f'{P}/devices/{DEVICE_TOPIC}', json={'value': 1})
        assert r.status_code == 405
        assert 'write-all=true' in r.text

    def test_multi_point_write_and_device_revert(self, api, P):
        r = api.put(f'{P}/devices/{DEVICE_TOPIC}', params={'write-all': 'true', 'confirm-values': 'true'},
                    json={'value': 7})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body[POINT]['value'] == 7.0 and body[POINT]['writable'] is True
        assert body[READ_ONLY_POINT]['writable'] is False
        r = api.delete(f'{P}/devices/{DEVICE_TOPIC}', params={'write-all': 'true', 'confirm-values': 'true'})
        assert r.status_code == 200, r.text
        assert r.json()[POINT]['value'] == 10.0

    def test_regex_selection(self, api, P):
        r = api.get(f'{P}/devices/{DEVICE_TOPIC}', params={'regex': 'SampleWritable.*'})
        assert r.status_code == 200, r.text
        links = r.json()['links']
        assert links and all(k.startswith('SampleWritable') for k in links)
        assert links['SampleWritableFloat1'] == f'{P}/devices/{POINT}'


# ---------------------------------------------------------------------------- /historians

class TestHistorians:
    def test_no_historians_installed(self, api, P):
        r = api.get(f'{P}/historians')
        assert r.status_code == 200
        assert r.json() == {'links': {}}

    def test_historian_links_are_static(self, api, P):
        r = api.get(f'{P}/historians/platform.historian')
        assert r.status_code == 200
        assert r.json() == {'links': {'topics': f'{P}/historians/platform.historian/topics'}}

    def test_topics_of_missing_historian_is_an_error_not_a_crash(self, api, P):
        r = api.get(f'{P}/historians/platform.historian/topics')
        assert r.status_code in (400, 500, 504), r.text
        assert 'error' in r.json()


# ---------------------------------------------------------------------------- /logs

class TestLogs:
    @pytest.fixture(scope='class')
    def logs_supported(self, api, P):
        r = api.get(f'{P}/logs')
        if r.status_code == 500 and 'list_logs' in r.text:
            pytest.skip('platform.control has no list_logs RPC in this core version')
        return r

    def test_list_logs(self, logs_supported):
        assert logs_supported.status_code == 200, logs_supported.text
        assert isinstance(logs_supported.json(), (list, dict))

    def test_read_log(self, api, P, logs_supported):
        body = logs_supported.json()
        logs = body['logs'] if isinstance(body, dict) else body
        assert logs, body
        log_id = logs[0]['id'] if isinstance(logs[0], dict) else logs[0]
        r = api.get(f'{P}/logs/{log_id}', params={'tail': 5})
        assert r.status_code == 200, r.text

    def test_bad_query_is_400(self, api, P):
        r = api.get(f'{P}/logs/anything', params={'tail': '0'})
        assert r.status_code == 400

    def test_unknown_platform_is_404(self, api):
        assert api.get('/vui/platforms/nope/logs').status_code == 404

    def test_post_is_501(self, api, P):
        assert api.post(f'{P}/logs', json={}).status_code == 501


# ---------------------------------------------------------------------------- /packaged-configs and /status

class TestPackagedConfigsAndStatus:
    def test_packaged_configs(self, api, P):
        r = api.get(f'{P}/packaged-configs')
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_packaged_configs_unknown_platform(self, api):
        assert api.get('/vui/platforms/nope/packaged-configs').status_code == 400

    def test_status(self, api, P):
        r = api.get(f'{P}/status')
        assert r.status_code == 200
        body = r.json()
        assert PLATFORM_DRIVER in body and body[PLATFORM_DRIVER]['running'] is True

    def test_clear_status(self, api, P):
        assert api.delete(f'{P}/status').status_code == 204
        assert api.get(f'{P}/status').status_code == 200


# ---------------------------------------------------------------------------- /pubsub

class TestPubsub:
    def test_publish(self, api, P):
        r = api.put(f'{P}/pubsub/e2e/test/topic', json={'headers': {'h': 1}, 'message': {'m': 2}})
        assert r.status_code == 200, r.text
        assert isinstance(r.json()['number_of_subscribers'], int)

    def test_socket_routes_initially_empty(self, api, P):
        r = api.get(f'{P}/pubsub')
        assert r.status_code == 200
        assert r.json() == {}

    def _ws_url(self, api, P, topic):
        return api.url.replace('http://', 'ws://') + f'{P}/pubsub/{topic}'

    def test_subscribe_receives_device_publish(self, api, P):
        topic = f'devices/{DEVICE_TOPIC}/multi'   # the modular driver publishes depth-first multi by default
        ws = websocket.create_connection(self._ws_url(api, P, topic),
                                         header=[f'Authorization: Bearer {api.access_token}'], timeout=30)
        try:
            message = json.loads(ws.recv())
        finally:
            ws.close()
        # The socket carries the bus message body only (no topic/headers envelope); a driver 'multi' publish is
        # [values, metadata].
        assert isinstance(message, list) and 'SampleWritableFloat1' in message[0]

    def test_subscribe_receives_web_publish(self, api, P):
        topic = 'e2e/roundtrip'
        ws = websocket.create_connection(self._ws_url(api, P, topic),
                                         header=[f'Authorization: Bearer {api.access_token}'], timeout=30)
        try:
            time.sleep(1)   # let the subscription settle
            r = api.put(f'{P}/pubsub/{topic}', json={'headers': {}, 'message': {'n': 1}})
            assert r.status_code == 200, r.text
            message = json.loads(ws.recv())
        finally:
            ws.close()
        assert message == {'n': 1}

    def test_socket_routes_list_open_subscription(self, api, P):
        topic = 'e2e/listed'
        ws = websocket.create_connection(self._ws_url(api, P, topic),
                                         header=[f'Authorization: Bearer {api.access_token}'], timeout=30)
        try:
            routes = wait_until(lambda: api.get(f'{P}/pubsub').json() or None, timeout=10,
                                message='open socket not listed')
            assert topic in routes
        finally:
            ws.close()

    def test_subscribe_without_token_is_rejected(self, api, P):
        with pytest.raises((websocket.WebSocketBadStatusException, websocket.WebSocketException)):
            websocket.create_connection(self._ws_url(api, P, 'e2e/anon'), timeout=10)

    def test_subscribe_with_garbage_token_is_rejected(self, api, P):
        with pytest.raises((websocket.WebSocketBadStatusException, websocket.WebSocketException)):
            websocket.create_connection(self._ws_url(api, P, 'e2e/anon'), header=['Authorization: Bearer nope'],
                                        timeout=10)

    def test_subscribe_with_refresh_token_is_rejected(self, api, P, tokens):
        with pytest.raises((websocket.WebSocketBadStatusException, websocket.WebSocketException)):
            websocket.create_connection(self._ws_url(api, P, 'e2e/anon'),
                                        header=[f"Authorization: Bearer {tokens['refresh_token']}"], timeout=10)
