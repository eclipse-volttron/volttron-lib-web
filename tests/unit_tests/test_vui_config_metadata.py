"""Config entry metadata over the VUI: ETag, Last-Modified and Config-Type headers, conditional requests, HEAD,
``metadata=true`` on the entry and listing routes, the write flags and If-Match."""
import json
from unittest import mock
from unittest.mock import MagicMock

import pytest
from werkzeug import Response

from volttron.client.known_identities import CONFIGURATION_STORE
from volttron.services.web.vui_endpoints import VUIEndpoints, _etag, _http_date, _not_modified

from test_vui_endpoints import _mock_agents_rpc
from web_utils import get_test_web_env, mock_platform_web_service

RUN1 = '/vui/platforms/my_instance_name/agents/run1'
CONFIG1_ETAG = _etag('json', json.dumps({'setting1': 1, 'setting2': 2}))
CSV_ETAG = _etag('csv', 'Point Name,Value\nA,1\n')


def _vui(mock_platform_web_service, rpc=None):
    vui = VUIEndpoints(mock_platform_web_service)
    vui._rpc = MagicMock(wraps=rpc or _mock_agents_rpc)
    return vui


def _with_modified(modified):
    """The mock store, with a modification time on every entry."""
    def rpc(peer, meth, *args, **kwargs):
        result = _mock_agents_rpc(peer, meth, *args, **kwargs)
        if peer == CONFIGURATION_STORE and meth == 'get_metadata':
            result = {**result, 'modified': modified}
        return result
    return rpc


def _wsgi_body(response: Response, env: dict) -> bytes:
    body, _status, _headers = response.get_wsgi_response(env)
    return b''.join(body)


# ---------------------------------------------------------------- headers on the entry GET
@pytest.mark.parametrize('config_name, accept, expected_type, expected_etag', [
    ('config1', None, 'json', CONFIG1_ETAG), ('config1', 'text/plain', 'json', CONFIG1_ETAG),
    ('points.csv', None, 'csv', CSV_ETAG), ('points.csv', 'text/csv', 'csv', CSV_ETAG)])
def test_entry_get_carries_etag_and_type(mock_platform_web_service, config_name, accept, expected_type, expected_etag):
    headers = {'HTTP_ACCEPT': accept} if accept else {}
    env = get_test_web_env(f'{RUN1}/configs/{config_name}', HTTP_AUTHORIZATION='Bearer foo', **headers)
    response = _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {})
    assert response.status_code == 200
    assert response.headers['ETag'] == expected_etag and response.headers['Config-Type'] == expected_type
    assert 'Last-Modified' not in response.headers          # the mock store predates the modified field


def test_etag_depends_on_type_as_well_as_text():
    assert _etag('json', '{}') != _etag('raw', '{}') and _etag('json', '{}').startswith('"') and len(_etag('json', '{}')) == 34


def test_last_modified_when_the_store_recorded_one(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo')
    response = _vui(mock_platform_web_service, _with_modified('2026-10-29T12:34:56.123456+00:00')).handle_platforms_agents_configs(env, {})
    assert response.headers['Last-Modified'] == 'Thu, 29 Oct 2026 12:34:56 GMT'
    assert _http_date('not a date') is None and _http_date(None) is None


def test_json_body_still_comes_from_get_config(mock_platform_web_service):
    vui = _vui(mock_platform_web_service)
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo')
    response = vui.handle_platforms_agents_configs(env, {})
    assert json.loads(response.get_data(as_text=True)) == {'setting1': 1, 'setting2': 2}
    vui._rpc.assert_any_call(CONFIGURATION_STORE, 'get_metadata', 'run1', 'config1', external_platform='my_instance_name')
    vui._rpc.assert_any_call(CONFIGURATION_STORE, 'get_config', 'run1', 'config1', raw=False, external_platform='my_instance_name')


def test_text_body_needs_no_second_rpc(mock_platform_web_service):
    vui = _vui(mock_platform_web_service)
    env = get_test_web_env(f'{RUN1}/configs/points.csv', HTTP_AUTHORIZATION='Bearer foo', HTTP_ACCEPT='text/csv')
    assert vui.handle_platforms_agents_configs(env, {}).get_data(as_text=True) == 'Point Name,Value\nA,1\n'
    assert [c.args[1] for c in vui._rpc.call_args_list if c.args[0] == CONFIGURATION_STORE] == ['get_metadata']


# ---------------------------------------------------------------- conditional requests
@pytest.mark.parametrize('header, value, status', [
    ('HTTP_IF_NONE_MATCH', CONFIG1_ETAG, 304), ('HTTP_IF_NONE_MATCH', f'"other", {CONFIG1_ETAG}', 304),
    ('HTTP_IF_NONE_MATCH', f'W/{CONFIG1_ETAG}', 304), ('HTTP_IF_NONE_MATCH', '*', 304),
    ('HTTP_IF_NONE_MATCH', '"stale"', 200)])
def test_if_none_match(mock_platform_web_service, header, value, status):
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo', **{header: value})
    response = _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {})
    assert response.status_code == status and response.headers['ETag'] == CONFIG1_ETAG
    if status == 304:
        assert response.get_data() == b''


@pytest.mark.parametrize('since, status', [
    ('Thu, 29 Oct 2026 12:34:56 GMT', 304), ('Fri, 30 Oct 2026 00:00:00 GMT', 304), ('Wed, 28 Oct 2026 00:00:00 GMT', 200),
    ('garbage', 200)])
def test_if_modified_since(mock_platform_web_service, since, status):
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_MODIFIED_SINCE=since)
    rpc = _with_modified('2026-10-29T12:34:56.000000+00:00')
    assert _vui(mock_platform_web_service, rpc).handle_platforms_agents_configs(env, {}).status_code == status


def test_if_modified_since_without_a_recorded_time_is_never_304(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_MODIFIED_SINCE='Fri, 30 Oct 2026 00:00:00 GMT')
    assert _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).status_code == 200
    assert _not_modified({'HTTP_IF_MODIFIED_SINCE': 'Fri, 30 Oct 2026 00:00:00 GMT'}, {'etag': '"x"', 'modified': None}) is False


def test_if_none_match_wins_over_if_modified_since(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_NONE_MATCH='"stale"',
                           HTTP_IF_MODIFIED_SINCE='Fri, 30 Oct 2026 00:00:00 GMT')
    assert _vui(mock_platform_web_service, _with_modified('2026-10-29T12:00:00+00:00')).handle_platforms_agents_configs(env, {}).status_code == 200


# ---------------------------------------------------------------- metadata instead of contents
def test_metadata_true_returns_the_metadata_object(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/points.csv', query_string='metadata=true', HTTP_AUTHORIZATION='Bearer foo')
    response = _vui(mock_platform_web_service, _with_modified('2026-10-29T12:00:00+00:00')).handle_platforms_agents_configs(env, {})
    assert response.status_code == 200 and response.headers['ETag'] == CSV_ETAG
    assert json.loads(response.get_data(as_text=True)) == {'type': 'csv', 'modified': '2026-10-29T12:00:00+00:00', 'etag': CSV_ETAG, 'size': len('Point Name,Value\nA,1\n')}


def test_metadata_true_still_answers_304(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', query_string='metadata=true', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_NONE_MATCH=CONFIG1_ETAG)
    assert _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).status_code == 304


# ---------------------------------------------------------------- HEAD
def test_head_has_the_headers_and_no_body(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', method='HEAD', HTTP_AUTHORIZATION='Bearer foo')
    response = _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {})
    assert response.status_code == 200 and response.headers['ETag'] == CONFIG1_ETAG and response.headers['Config-Type'] == 'json'
    assert _wsgi_body(response, env) == b''                 # werkzeug strips the body for HEAD
    get_env = get_test_web_env(f'{RUN1}/configs/config1', HTTP_AUTHORIZATION='Bearer foo')
    assert _wsgi_body(_vui(mock_platform_web_service).handle_platforms_agents_configs(get_env, {}), get_env) != b''


def test_head_is_conditional_too(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/config1', method='HEAD', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_NONE_MATCH=CONFIG1_ETAG)
    assert _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).status_code == 304


def test_head_on_the_listing(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs', method='HEAD', HTTP_AUTHORIZATION='Bearer foo')
    response = _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {})
    assert response.status_code == 200 and _wsgi_body(response, env) == b''


# ---------------------------------------------------------------- listings with metadata
def test_listing_with_metadata(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs', query_string='metadata=true', HTTP_AUTHORIZATION='Bearer foo')
    body = json.loads(_vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).get_data(as_text=True))
    assert set(body['links']) == {'config1', 'config2'}      # the plain listing is still there
    assert body['configs']['config1'] == {'type': 'json', 'modified': None, 'etag': CONFIG1_ETAG, 'size': len(json.dumps({'setting1': 1, 'setting2': 2})), 'link': f'{RUN1}/configs/config1'}


def test_plain_listing_is_unchanged(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs', HTTP_AUTHORIZATION='Bearer foo')
    body = json.loads(_vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).get_data(as_text=True))
    assert set(body) == {'links'}


def test_store_listing_with_metadata_counts_entries(mock_platform_web_service):
    env = get_test_web_env('/vui/platforms/my_instance_name/agents/-/configs', query_string='metadata=true', HTTP_AUTHORIZATION='Bearer foo')
    body = json.loads(_vui(mock_platform_web_service).handle_platforms_agents_configs(env, {}).get_data(as_text=True))
    assert body == {'run1': {'configs': 2}, 'run2': {'configs': 2}}


# ---------------------------------------------------------------- write flags and If-Match
@pytest.mark.parametrize('query, expected_flags', [
    ('', {}), ('send-update=false', {'send_update': False}), ('trigger-callback=false&send-update=false', {'trigger_callback': False, 'send_update': False}),
    ('send-update=true', {})])
def test_write_flags_forwarded_only_when_off(mock_platform_web_service, query, expected_flags):
    vui = _vui(mock_platform_web_service)
    env = get_test_web_env(f'{RUN1}/configs/config1', method='PUT', query_string=query, CONTENT_TYPE='application/json', HTTP_AUTHORIZATION='Bearer foo')
    assert vui.handle_platforms_agents_configs(env, {'a': 1}).status_code == 204
    vui._rpc.assert_any_call(CONFIGURATION_STORE, 'set_config', 'run1', 'config1', '{"a": 1}', 'json', external_platform='my_instance_name', **expected_flags)


def test_post_takes_the_flags_too(mock_platform_web_service):
    vui = _vui(mock_platform_web_service)
    env = get_test_web_env(f'{RUN1}/configs', method='POST', query_string='config-name=new&send-update=false', CONTENT_TYPE='application/json', HTTP_AUTHORIZATION='Bearer foo')
    assert vui.handle_platforms_agents_configs(env, {'a': 1}).status_code == 201
    vui._rpc.assert_any_call(CONFIGURATION_STORE, 'set_config', 'run1', 'new', '{"a": 1}', 'json', external_platform='my_instance_name', send_update=False)


@pytest.mark.parametrize('if_match, status', [(CONFIG1_ETAG, 204), ('*', 204), ('"stale"', 412), (f'"stale", {CONFIG1_ETAG}', 204)])
def test_if_match_on_put(mock_platform_web_service, if_match, status):
    vui = _vui(mock_platform_web_service)
    env = get_test_web_env(f'{RUN1}/configs/config1', method='PUT', CONTENT_TYPE='application/json', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_MATCH=if_match)
    response = vui.handle_platforms_agents_configs(env, {'a': 1})
    assert response.status_code == status
    if status == 412:
        assert json.loads(response.get_data(as_text=True))['etag'] == CONFIG1_ETAG
        assert not any(c.args[1] == 'set_config' for c in vui._rpc.call_args_list)


def test_if_match_on_a_missing_entry_is_412(mock_platform_web_service):
    env = get_test_web_env(f'{RUN1}/configs/does_not_exist', method='PUT', CONTENT_TYPE='application/json', HTTP_AUTHORIZATION='Bearer foo', HTTP_IF_MATCH='"anything"')
    assert _vui(mock_platform_web_service).handle_platforms_agents_configs(env, {'a': 1}).status_code == 412
