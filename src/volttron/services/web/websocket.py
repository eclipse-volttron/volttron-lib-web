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

import logging

from ws4py.websocket import WebSocket

_log = logging.getLogger(__name__)


class VolttronWebSocket(WebSocket):

    def __init__(self, *args, **kwargs):
        super(VolttronWebSocket, self).__init__(*args, **kwargs)
        _log = logging.getLogger(self.__class__.__name__)

    def _get_identity_and_endpoint(self):
        identity = self.environ['identity']
        endpoint = self.environ['PATH_INFO']
        return identity, endpoint

    def opened(self):
        _log.info('Socket opened')
        app = self.environ['ws4py.app']
        identity, endpoint = self._get_identity_and_endpoint()
        app.client_opened(self, endpoint, identity)

    def received_message(self, m):
        # self.clients is set from within the server
        # and holds the list of all connected servers
        # we can dispatch to
        _log.debug('Socket received message: {}'.format(m))
        app = self.environ['ws4py.app']
        identity, endpoint = self._get_identity_and_endpoint()
        app.client_received(endpoint, m)

    def closed(self, code, reason="A client left the room without a proper explanation."):
        _log.info('Socket closed!')
        app = self.environ.pop('ws4py.app')
        identity, endpoint = self._get_identity_and_endpoint()
        app.client_closed(self, endpoint, identity, reason)
