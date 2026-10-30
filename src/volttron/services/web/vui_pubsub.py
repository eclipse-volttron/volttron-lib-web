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

"""Websocket subscriptions of the VUI pubsub endpoints.

A subscription websocket belongs to the login session whose access token opened it. The
manager keeps the open sockets per session so that revoking the session closes them, and
each socket's message-bus subscription is released when the socket closes.
"""

import json
import logging
from collections import defaultdict

from ws4py.server.wsgiutils import WebSocketWSGIApplication
from ws4py.websocket import WebSocket

from .token_revocation import session_id

_log = logging.getLogger(__name__)

# Close code for a socket the server closes for an authorization reason (RFC 6455 "policy violation").
POLICY_VIOLATION = 1008


class VUIPubsubManager:
    def __init__(self, agent):
        self._agent = agent
        self._sockets = defaultdict(set)    # login session id -> open VUIWebSockets of that session

    # ------------------------------------------------------------------ tokens

    def verify_token(self, access_token):
        """Return the verified claims of a live access token in the ``vui`` group, or None.

        Goes through the web service's ``get_user_claims`` so that the signature, expiry, grant type and
        session revocation are all checked in one place. Never raises.
        """
        if not access_token:
            return None
        try:
            claims = self._agent.get_user_claims(access_token) or {}
        except Exception as e:
            _log.debug(f'Websocket token did not validate: {e.__class__.__name__}')
            return None
        groups = claims.get('groups')
        if not isinstance(groups, (list, tuple, set)) or 'vui' not in groups:
            return None
        return claims

    # ------------------------------------------------------------------ endpoint API

    def open_subscription_socket(self, access_token, topic, sid=None):
        """Return the WSGI application that completes the websocket handshake for ``topic``.

        The socket verifies its token and registers itself through :meth:`client_opened` once ws4py has opened it;
        ``access_token`` and ``sid`` are accepted for callers that pass them but nothing is recorded before then.
        """
        _log.debug(f'Opening subscription websocket for topic {topic!r}')
        return WebSocketWSGIApplication(handler_cls=VUIWebSocket)

    def get_socket_routes(self, access_token, topic=None):
        """The topics with open websockets for the login session of ``access_token``."""
        sid = session_id(self.verify_token(access_token))
        return {ws.vui_topic: str(ws) for ws in self._sockets.get(sid, ()) if not ws.terminated}

    def publish(self, topic, headers, message):
        subscriber_count = self._agent.vip.pubsub.publish('pubsub', topic, headers=headers, message=message).get(timeout=5)
        return {'number_of_subscribers': subscriber_count}

    # ------------------------------------------------------------------ socket lifecycle

    def client_opened(self, ws, topic, access_token, claims):
        """Record an opened socket under its login session and subscribe it to ``topic``."""
        ws.vui_topic = topic
        ws.vui_token = access_token
        ws.vui_sid = session_id(claims)
        _log.debug(f'VUIPubsubManager: subscribing a websocket to {topic!r}')
        self._agent.vip.pubsub.subscribe('pubsub', topic, ws.on_topic)
        self._sockets[ws.vui_sid].add(ws)

    def client_closed(self, ws):
        """Forget a socket and release its message-bus subscription. Idempotent; returns True when it did anything."""
        sid = getattr(ws, 'vui_sid', None)
        sockets = self._sockets.get(sid)
        if sockets is None or ws not in sockets:
            return False
        sockets.discard(ws)
        if not sockets:
            del self._sockets[sid]
        try:
            self._agent.vip.pubsub.unsubscribe('pubsub', ws.vui_topic, ws.on_topic)
        except Exception as e:
            _log.warning(f'Could not unsubscribe a closed websocket from {ws.vui_topic!r}: {e.__class__.__name__}')
        return True

    def close_socket(self, ws, reason, code=POLICY_VIOLATION):
        """Release a socket's subscription and close it. Returns True when a live socket was closed."""
        self.client_closed(ws)
        if ws.terminated:
            return False
        try:
            ws.close(code=code, reason=reason)
        except Exception as e:
            _log.warning(f'Could not close a websocket ({reason}): {e.__class__.__name__}')
            return False
        return True

    def close_session_sockets(self, sid):
        """Close every websocket of the revoked login session ``sid``. Returns the number closed."""
        return sum(1 for ws in list(self._sockets.get(sid, ())) if self.close_socket(ws, 'Session revoked'))


class VUIWebSocket(WebSocket):
    """One client's subscription to one topic."""

    def _get_topic(self):
        from volttron.services.web import get_bearer
        topic = self.environ['PATH_INFO'].split('/pubsub/')[1]
        try:
            access_token = get_bearer(self.environ)
        except Exception:    # no token, or a malformed Authorization header
            access_token = None
        return topic, access_token

    def opened(self):
        app = self.environ['ws4py.app']
        topic, access_token = self._get_topic()
        # The HTTP upgrade request was authorized by the VUI endpoint, but the websocket outlives the request.
        # Verify again here so a socket is never subscribed for a token that does not carry the vui group.
        claims = app.verify_token(access_token)
        if claims is None:
            _log.warning(f'Closing websocket for {topic!r}: token did not validate or lacks the vui group.')
            self.close(code=POLICY_VIOLATION, reason='Not Authorized')
            return
        app.client_opened(self, topic, access_token, claims)

    def received_message(self, m):
        pass

    def closed(self, code, reason=None):
        app = self.environ.get('ws4py.app') if hasattr(self, 'environ') else None
        if app is not None:
            app.client_closed(self)

    def on_topic(self, peer, sender, bus, topic, headers, message):
        if self.terminated:
            return
        try:
            self.send(json.dumps(message))
        except Exception as e:
            _log.warning(f'Error sending subscription data: {e}')
