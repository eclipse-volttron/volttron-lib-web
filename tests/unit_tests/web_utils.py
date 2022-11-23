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

import pytest

from io import BytesIO
from mock import Mock, MagicMock, patch

from volttron.client.vip.agent import Agent
from volttron.client.vip.agent.results import AsyncResult
from volttron.services.web.platform_web_service import PlatformWebService
from volttron.utils.messagebus import store_message_bus_config

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ
from volttrontesting.utils import AgentMock


class QueryHelper:
    """
    Query helper allows us to mock out the Query subsystem and return default
    values for calls to it.
    """

    def __init__(self, core):
        pass

    def query(self, name):
        result = AsyncResult()
        result.set_result('my_instance_name')
        return result


@pytest.fixture()
def mock_platform_web_service() -> PlatformWebService:
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        bases = PlatformWebService.__bases__
        PlatformWebService.__bases__ = (AgentMock.imitate(Agent, Agent()),)
        with patch(target='volttron.services.web.vui_endpoints.Query', new=QueryHelper):
            platform_web = PlatformWebService(server_config=MagicMock(),
                                              bind_web_address=MagicMock(),
                                              serverkey=MagicMock(),
                                              identity=MagicMock(),
                                              address=MagicMock())
            # Internally the register uses this value to determine the caller's identity
            # to allow the platform web service to map calls back to the proper agent
            platform_web.vip.rpc.context.vip_message.peer.return_value = "foo"
            platform_web.core.volttron_home = volttron_home
            platform_web.core.instance_name = 'my_instance_name'
            platform_web.get_user_claims = lambda x: {'groups': ['vui']}

            yield platform_web
        PlatformWebService.__bases__ = bases

def get_test_web_env(path, input_data: bytes = None, query_string='', url_scheme='http', method='GET',
                     **kwargs) -> dict:
    """
    Constructs the environment that gets passed to a wsgi application during a request
    from client to server.  The response will return a valid env that can be passed
    into the applications "run" path.

    :param path: the endpoint/file/websocket to call
    :param input_data:  input data to be passed into the request (must be a ByteIO object)
    :param query_string: form or other data to be used as input to the environment.
    :param url_scheme: the scheme used to set the environment (http, https, ws, wss)
    :param method: REQUEST_METHOD used for this request (GET, POST, PUT etc)

    :return: A dictionary to be passed to the app_routing function in the platformwebservice
    """
    if path is None:
        raise ValueError("Invalid path specified.  Cannot be None.")
    byte_data = BytesIO()
    len_input_data = 0
    if input_data is not None:
        byte_data.write(input_data)
        byte_data.seek(0)
        len_input_data = len(input_data)

    if url_scheme not in ('http', 'https', 'ws', 'wss'):
        raise ValueError(f"Invalid url_scheme specified {url_scheme}")
    stdenvvars = {
        'SERVER_NAME': 'v2',
        'SERVER_PORT': '8080',
        'REQUEST_METHOD': method,
        # Replace the PATH_INFO in each test to customize the location/endpoint of
        # the functionality.
        'PATH_INFO': path,
        'QUERY_STRING': query_string,
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'REMOTE_ADDR': '192.168.56.101',
        'REMOTE_PORT': '44016',
        'HTTP_HOST': 'v2:8080',
        'HTTP_CONNECTION': 'keep-alive',
        'HTTP_CACHE_CONTROL': 'max-age=0',
        'HTTP_UPGRADE_INSECURE_REQUESTS':  '1',
        'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36',
        'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
        'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
        'HTTP_ACCEPT_LANGUAGE': 'en-US,en;q=0.9',
        'CONTENT_LENGTH': len_input_data,
        'wsgi.input': byte_data,  # input_data,  # {Input} <gevent.pywsgi.Input object at 0x7fd11882a588>
        'wsgi.input_terminated': True,
        'wsgi.url_scheme': url_scheme,
        "JINJA2_TEMPLATE_ENV": Mock()
        # ,
        # 'CONTENT_LENGTH': len(input_data.getvalue().decode('utf-8'))
    }

    # Use kwargs passed and add them to the stdvars and make them available
    # in the environment.
    for k, v in kwargs.items():
        stdenvvars[k] = v

    return stdenvvars
