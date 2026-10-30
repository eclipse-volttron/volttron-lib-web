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

    @pytest.mark.parametrize('body', [{'username': ['a'], 'password': PASSWORD}, {'username': USERNAME, 'password': 7},
                                      'text', ['a', 'b'], 7])
    def test_malformed_login_input_is_401_not_500(self, base_url, body):
        r = requests.post(f'{base_url}/authenticate', json=body, timeout=10)
        assert r.status_code == 401, r.text

    def test_non_json_login_body_with_json_content_type_is_400(self, base_url):
        r = requests.post(f'{base_url}/authenticate', data=b'{bad json', headers={'Content-Type': 'application/json'},
                          timeout=10)
        assert r.status_code == 400, r.text
        assert r.json() == {'error': 'Malformed JSON body'}

    @pytest.mark.parametrize('body', ['"x"', '[1]', '7'])
    def test_renew_with_a_non_object_body_is_401_not_500(self, base_url, body):
        fresh = requests.post(f'{base_url}/authenticate', json={'username': USERNAME, 'password': PASSWORD},
                              timeout=10).json()
        r = requests.put(f'{base_url}/authenticate', data=body,
                         headers={'Authorization': f"Bearer {fresh['refresh_token']}", 'Content-Type': 'application/json'},
                         timeout=10)
        assert r.status_code == 401, r.text

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

    def test_revoke_logs_the_whole_session_out(self, base_url):
        fresh = requests.post(f'{base_url}/authenticate', json={'username': USERNAME, 'password': PASSWORD},
                              timeout=10).json()
        access = {'Authorization': f"Bearer {fresh['access_token']}"}
        refresh = {'Authorization': f"Bearer {fresh['refresh_token']}"}
        renewed = requests.put(f'{base_url}/authenticate', json={}, headers=refresh, timeout=10).json()
        renewed_access = {'Authorization': f"Bearer {renewed['access_token']}"}
        assert requests.get(f'{base_url}/vui/platforms', headers=access, timeout=10).status_code == 200
        # Neither no token nor the cookie alone logs anyone out.
        assert requests.delete(f'{base_url}/authenticate', timeout=10).status_code == 401
        assert requests.delete(f'{base_url}/authenticate', cookies={'Bearer': fresh['access_token']},
                               timeout=10).status_code == 401
        assert requests.get(f'{base_url}/vui/platforms', headers=access, timeout=10).status_code == 200

        r = requests.delete(f'{base_url}/authenticate', headers=refresh, timeout=10)
        assert r.status_code == 204 and r.content == b''
        assert requests.get(f'{base_url}/vui/platforms', headers=access, timeout=10).status_code == 401
        assert requests.get(f'{base_url}/vui/platforms', headers=renewed_access, timeout=10).status_code == 401
        assert requests.get(f'{base_url}/admin/index.html', headers=access, timeout=10).status_code == 401
        assert requests.put(f'{base_url}/authenticate', json={}, headers=refresh, timeout=10).status_code == 401
        # Idempotent, and other sessions are untouched.
        assert requests.delete(f'{base_url}/authenticate', headers=refresh, timeout=10).status_code == 204
        assert requests.delete(f'{base_url}/authenticate', headers=access, timeout=10).status_code == 204

    def test_revoke_with_bad_token_is_401(self, base_url, api):
        assert requests.delete(f'{base_url}/authenticate', headers={'Authorization': 'Bearer nope'},
                               timeout=10).status_code == 401
        assert api.get('/vui/platforms').status_code == 200

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

    def test_cookie_authenticates_reads_but_not_writes(self, base_url, tokens, P):
        cookies = {'Bearer': tokens['access_token']}
        assert requests.get(f'{base_url}/vui/platforms', cookies=cookies, timeout=10).status_code == 200
        r = requests.put(f'{base_url}{P}/pubsub/e2e/cookie-write', cookies=cookies,
                         json={'headers': {}, 'message': 1}, timeout=10)
        assert r.status_code == 401
        r = requests.put(f'{base_url}{P}/pubsub/e2e/cookie-write', cookies=cookies,
                         headers={'Authorization': f"Bearer {tokens['access_token']}"},
                         json={'headers': {}, 'message': 1}, timeout=10)
        assert r.status_code == 200

    def test_refresh_token_is_not_accepted_for_api(self, base_url, tokens):
        r = requests.get(f'{base_url}/vui', headers={'Authorization': f"Bearer {tokens['refresh_token']}"}, timeout=10)
        assert r.status_code == 401   # not an access token: log in, rather than lacking a group

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


    # ---- selecting several agents with the '-' wildcard ----------------------------------------------------------
    def test_wildcard_agent_links(self, api, P):
        r = api.get(f'{P}/agents/-')
        assert r.status_code == 200
        assert set(r.json()['links']) == {'running', 'enabled', 'status', 'health'}

    def test_select_running_by_tag(self, api, P):
        r = api.get(f'{P}/agents/-/running', params={'tag': 'listener'})
        assert r.status_code == 200, r.text
        assert r.json() == {LISTENER: {'running': True}}

    def test_select_any_tagged_excludes_platform_services(self, api, P):
        body = api.get(f'{P}/agents/-/running', params={'tag': '*'}).json()
        assert {LISTENER, PLATFORM_DRIVER} <= set(body)          # installed, tagged agents (the driver is one)
        hidden = {'platform.web', 'platform.health', 'platform.control', 'platform.auth', 'platform.config_store'}
        assert hidden.isdisjoint(body)                            # platform services never match without include-hidden

    def test_select_by_regex_with_hidden(self, api, P):
        body = api.get(f'{P}/agents/-/running',
                       params={'regex': r'^platform\.(web|health)$', 'include-hidden': 'true'}).json()
        assert set(body) == {'platform.web', 'platform.health'}
        assert all(v == {'running': True} for v in body.values())

    def test_select_invalid_regex_is_400(self, api, P):
        assert api.get(f'{P}/agents/-/running', params={'regex': '('}).status_code == 400

    def test_select_without_filter_is_400(self, api, P):
        for method in ('get', 'put', 'delete'):
            r = getattr(api, method)(f'{P}/agents/-/running')
            assert r.status_code == 400, r.text
            assert 'requires a tag or regex' in r.json()['error']
        assert api.get(f'{P}/agents/{LISTENER}/running').json() == {'running': True}   # nothing was stopped

    def test_select_stop_and_start_by_tag(self, api, P):
        r = api.delete(f'{P}/agents/-/running', params={'tag': 'listener'})
        assert r.status_code == 200, r.text
        assert r.json() == {LISTENER: {'running': False, 'error': None}}
        assert api.get(f'{P}/agents/{LISTENER}/running').json() == {'running': False}
        r = api.put(f'{P}/agents/-/running', params={'tag': 'listener'})
        assert r.status_code == 200, r.text
        assert r.json()[LISTENER]['error'] is None
        wait_until(lambda: api.get(f'{P}/agents/{LISTENER}/running').json()['running'], message='listener restart')

    def test_select_enabled_by_tag(self, api, P):
        r = api.put(f'{P}/agents/-/enabled', params={'tag': 'listener', 'priority': '20'})
        assert r.status_code == 200, r.text
        assert r.json() == {LISTENER: {'status': True, 'priority': 20, 'error': None}}
        assert api.get(f'{P}/agents/-/enabled', params={'tag': 'listener'}).json() == \
               {LISTENER: {'status': True, 'priority': 20}}
        r = api.delete(f'{P}/agents/-/enabled', params={'tag': 'listener'})
        assert r.json() == {LISTENER: {'status': False, 'priority': None, 'error': None}}

    def test_select_status(self, api, P):
        body = api.get(f'{P}/agents/-/status', params={'tag': '*'}).json()
        assert {LISTENER, PLATFORM_DRIVER} <= set(body)
        assert body[LISTENER]['running'] is True and body[LISTENER]['tag'] == 'listener'

    def test_agents_list_tag_filter(self, api, P):
        assert set(api.get(f'{P}/agents', params={'tag': 'listener'}).json()['links']) == {LISTENER}
        assert set(api.get(f'{P}/agents', params={'regex': r'^platform\.dr'}).json()['links']) == {PLATFORM_DRIVER}

    # ---- health ----------------------------------------------------------------------------------------------------
    def test_agent_health(self, api, P):
        r = api.get(f'{P}/agents/{LISTENER}/health')
        assert r.status_code == 200, r.text
        assert {'peer', 'connected', 'last_heartbeat', 'message'} <= set(r.json())
        assert api.get(f'{P}/agents/no.such.agent/health').status_code == 400

    def test_agent_health_selection_and_platform_health(self, api, P):
        assert set(api.get(f'{P}/agents/-/health', params={'tag': 'listener'}).json()) == {LISTENER}
        body = api.get(f'{P}/health').json()
        # The health service lists the agents that report health (the listener sends heartbeats; the driver does not).
        assert LISTENER in body and {'peer', 'connected', 'last_heartbeat', 'message'} <= set(body[LISTENER])
        assert api.get('/vui/platforms/nope/health').status_code == 400


# ---------------------------------------------------------------------------- /agents/:id/configs

class TestSpecParityAndSelection:
    def test_invalid_regex_on_the_wildcard_agent_route_is_400(self, api, P):
        r = api.get(f'{P}/agents/-?regex=(')
        assert r.status_code == 400 and 'Invalid regex' in r.json()['error']
        assert api.get(f'{P}/agents/-?regex=.').status_code == 200

    @pytest.mark.parametrize('path', ['/vui/keypair', '/vui/devices', '/vui/historians', '{P}/auths', '{P}/roles',
                                      '{P}/groups', '{P}/known-hosts', '{P}/statistics', '{P}/configs',
                                      '{P}/agents/listener/frontends'])
    def test_spec_paths_without_an_implementation_are_501(self, api, P, path):
        r = api.get(path.format(P=P))
        assert r.status_code == 501, r.text
        assert 'not implemented' in r.json()['error']

    def test_spec_path_without_a_token_is_401_not_404(self, base_url):
        assert requests.get(f'{base_url}/vui/keypair', timeout=10).status_code == 401


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

    def test_config_write_without_capability_is_403(self, api, P):
        # Runs before test_config_crud requests the grant: platform.web has only libauth's default control.*
        # capabilities, so the platform refuses the write and the web reports its own lack of privilege.
        r = api.put(f'{P}/agents/e2e.config.agent/configs/denied', json={'a': 1})
        assert r.status_code == 403, r.text
        body = r.json()
        assert 'not authorized by the platform' in body['error']
        assert 'platform.config_store.set_config' in body['detail']
        assert api.delete(f'{P}/agents/e2e.config.agent/configs/denied').status_code == 403
        assert api.delete(f'{P}/agents/e2e.config.agent/configs').status_code == 403

    def test_config_crud(self, api, P, config_write_capability):
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
        r = api.delete(base)                                     # 'notes' is still in the store
        assert r.status_code == 409, r.text
        assert r.json()['configs'] == ['notes']
        assert api.delete(base, params={'all': 'true'}).status_code == 204
        assert agent not in api.get(f'{P}/agents/-/configs').json()
        assert api.delete(base).status_code == 204               # deleting an empty or absent store needs no consent

    def test_config_entry_metadata_headers_and_conditional_requests(self, api, P, config_write_capability):
        base = f'{P}/agents/e2e.config.agent/configs'
        assert api.put(f'{base}/meta', json={'a': 1}).status_code == 204
        r = api.get(f'{base}/meta')
        assert r.status_code == 200 and r.headers['Config-Type'] == 'json'
        etag = r.headers['ETag']
        assert etag.startswith('"') and etag.endswith('"') and 'Last-Modified' in r.headers
        assert api.get(f'{base}/meta', headers={'If-None-Match': etag}).status_code == 304
        assert api.get(f'{base}/meta', headers={'If-None-Match': '"stale"'}).status_code == 200
        assert api.get(f'{base}/meta', headers={'If-Modified-Since': r.headers['Last-Modified']}).status_code == 304
        head = api.head(f'{base}/meta')
        assert head.status_code == 200 and head.headers['ETag'] == etag and head.content == b''
        assert api.head(f'{base}/meta', headers={'If-None-Match': etag}).status_code == 304
        meta = api.get(f'{base}/meta', params={'metadata': 'true'}).json()
        assert meta['type'] == 'json' and meta['etag'] == etag and meta['size'] == len('{"a": 1}') and meta['modified']
        listing = api.get(base, params={'metadata': 'true'}).json()
        assert listing['configs']['meta']['etag'] == etag and 'meta' in listing['links']
        assert api.get(f'{P}/agents/-/configs', params={'metadata': 'true'}).json()['e2e.config.agent']['configs'] >= 1
        # a write with a stale If-Match is refused and nothing changes; a matching one goes through and moves the ETag
        assert api.put(f'{base}/meta', json={'a': 2}, headers={'If-Match': '"stale"'}).status_code == 412
        assert api.get(f'{base}/meta').json() == {'a': 1}
        assert api.put(f'{base}/meta', json={'a': 2}, headers={'If-Match': etag}).status_code == 204
        assert api.get(f'{base}/meta').headers['ETag'] != etag
        assert api.put(f'{base}/quiet', json={'b': 1}, params={'send-update': 'false'}).status_code == 204
        assert api.get(f'{base}/quiet').json() == {'b': 1}
        assert api.delete(base, params={'all': 'true'}).status_code == 204

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

    def test_revoking_the_session_closes_its_websocket(self, base_url, api, P):
        fresh = requests.post(f'{base_url}/authenticate', json={'username': USERNAME, 'password': PASSWORD},
                              timeout=10).json()
        topic = f'devices/{DEVICE_TOPIC}/multi'   # published every scrape, so recv() returns promptly
        ws = websocket.create_connection(self._ws_url(api, P, topic),
                                         header=[f"Authorization: Bearer {fresh['access_token']}"], timeout=30)
        try:
            ws.recv()   # subscribed and receiving
            r = requests.delete(f'{base_url}/authenticate',
                                headers={'Authorization': f"Bearer {fresh['refresh_token']}"}, timeout=10)
            assert r.status_code == 204
            deadline = time.time() + 30
            closed = False
            while time.time() < deadline and not closed:
                try:
                    frame = ws.recv_frame()
                except websocket.WebSocketConnectionClosedException:
                    closed = True
                else:
                    closed = frame.opcode == websocket.ABNF.OPCODE_CLOSE
            assert closed, 'websocket of the revoked session stayed open'
        finally:
            ws.close()

    def test_cookie_subscribe_needs_a_same_origin_page(self, base_url, api, P):
        topic = 'e2e/cookie-origin'
        cookie = f"Bearer={api.access_token}"
        host = base_url.split('//', 1)[1]
        # No Origin, or another site's Origin: refused before any socket is opened. (websocket-client sends an
        # Origin matching the URL unless told not to.)
        for extra in ({'suppress_origin': True}, {'origin': 'http://evil.example'}):
            with pytest.raises((websocket.WebSocketBadStatusException, websocket.WebSocketException)):
                websocket.create_connection(self._ws_url(api, P, topic), cookie=cookie, timeout=10, **extra)
        # A page served by this host may open the socket with the cookie.
        ws = websocket.create_connection(self._ws_url(api, P, topic), cookie=cookie, origin=f'http://{host}',
                                         timeout=30)
        try:
            time.sleep(1)
            assert api.put(f'{P}/pubsub/{topic}', json={'headers': {}, 'message': {'via': 'cookie'}}).status_code == 200
            assert json.loads(ws.recv()) == {'via': 'cookie'}
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
