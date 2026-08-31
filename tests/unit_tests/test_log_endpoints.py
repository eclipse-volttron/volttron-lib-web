import json
from unittest.mock import MagicMock, patch
import pytest

from volttron.services.web.vui_endpoints import VUIEndpoints
from volttron.client.known_identities import CONTROL


@pytest.fixture
def vui_endpoints():
    mock_agent = MagicMock()
    mock_agent.get_user_claims.return_value = {"groups": ["vui"]}
    mock_agent.core.identity = "platform.web"
    
    mock_query_res = MagicMock()
    mock_query_res.get.return_value = "local"
    with patch("volttron.services.web.vui_endpoints.Query") as mock_query_cls:
        mock_query_cls.return_value.query.return_value = mock_query_res
        endpoints = VUIEndpoints(mock_agent)
    endpoints._get_platforms = MagicMock(return_value=["local", "remote_platform"])
    return endpoints


def test_handle_platforms_logs_success(vui_endpoints):
    expected_result = {
        "logs": [
            {
                "id": "abc1234567890def",
                "name": "volttron.log",
                "file_id": "fed0987654321cba",
                "size_bytes": 1024,
                "modified": 1723000000.0,
                "is_active": True,
            }
        ],
        "retention": {
            "max_file_bytes": 1048576,
            "backup_count": 5,
            "max_total_bytes": 6291456,
        },
    }
    vui_endpoints._rpc = MagicMock(return_value=expected_result)

    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/local/logs",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs(env, {})
    assert response.status_code == 200
    assert json.loads(response.response[0]) == expected_result
    vui_endpoints._rpc.assert_called_once_with(CONTROL, "list_logs", external_platform="local")


def test_handle_platforms_logs_remote_platform(vui_endpoints):
    expected_result = {"logs": [], "retention": None}
    vui_endpoints._rpc = MagicMock(return_value=expected_result)

    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/remote_platform/logs",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs(env, {})
    assert response.status_code == 200
    vui_endpoints._rpc.assert_called_once_with(CONTROL, "list_logs", external_platform="remote_platform")


def test_handle_platforms_logs_unknown_platform(vui_endpoints):
    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/unknown_platform/logs",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs(env, {})
    assert response.status_code == 404
    body = json.loads(response.response[0])
    assert "Unknown platform" in body.get("error", "")


def test_handle_platforms_logs_log_success(vui_endpoints):
    expected_read = {
        "lines": ["log line 1", "log line 2"],
        "start_offset": 0,
        "next_offset": 24,
        "previous_offset": 0,
        "total_bytes": 24,
        "file_id": "fed0987654321cba",
        "log_id": "abc1234567890def",
        "has_older": False,
        "has_newer": False,
    }
    vui_endpoints._rpc = MagicMock(return_value=expected_read)

    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/local/logs/abc1234567890def",
        "QUERY_STRING": "tail=50&bytes=1000",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs_log(env, {})
    assert response.status_code == 200
    assert json.loads(response.response[0]) == expected_read
    vui_endpoints._rpc.assert_called_once_with(
        CONTROL,
        "read_log",
        "abc1234567890def",
        tail=50,
        offset=None,
        before=None,
        max_bytes=1000,
        external_platform="local",
    )


def test_handle_platforms_logs_log_invalid_params(vui_endpoints):
    # offset and before cannot be combined
    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/local/logs/abc1234567890def",
        "QUERY_STRING": "offset=100&before=200",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs_log(env, {})
    assert response.status_code == 400


def test_handle_platforms_logs_log_not_found(vui_endpoints):
    vui_endpoints._rpc = MagicMock(side_effect=FileNotFoundError("Log file not found"))

    env = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/local/logs/missing_id",
        "QUERY_STRING": "",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    response = vui_endpoints.handle_platforms_logs_log(env, {})
    assert response.status_code == 404


def test_integration_vui_endpoints_with_core_log_reader(tmp_path, vui_endpoints):
    from volttron.server.logs import get_available_logs, read_log_file

    log_file = tmp_path / "volttron.log"
    log_file.write_text("Line 1\nLine 2\nLine 3\n")

    def mock_rpc_call(vip_identity, method, *args, external_platform=None, **kwargs):
        if method == "list_logs":
            return get_available_logs(volttron_home=str(tmp_path))
        elif method == "read_log":
            return read_log_file(*args, **kwargs, volttron_home=str(tmp_path))
        raise NotImplementedError(method)

    vui_endpoints._rpc = MagicMock(side_effect=mock_rpc_call)

    # 1. List logs via VUI
    env_list = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/vui/platforms/local/logs",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    res_list = vui_endpoints.handle_platforms_logs(env_list, {})
    assert res_list.status_code == 200
    list_body = json.loads(res_list.response[0])
    assert len(list_body["logs"]) == 1
    log_id = list_body["logs"][0]["id"]
    assert list_body["logs"][0]["name"] == "volttron.log"

    # 2. Read log via VUI using neutral log_id
    env_read = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": f"/vui/platforms/local/logs/{log_id}",
        "QUERY_STRING": "tail=2",
        "HTTP_AUTHORIZATION": "Bearer valid_token",
    }
    res_read = vui_endpoints.handle_platforms_logs_log(env_read, {})
    assert res_read.status_code == 200
    read_body = json.loads(res_read.response[0])
    assert read_body["lines"] == ["Line 2", "Line 3"]
    assert read_body["total_bytes"] == log_file.stat().st_size

