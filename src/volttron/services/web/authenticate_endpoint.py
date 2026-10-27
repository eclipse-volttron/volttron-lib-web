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
import os
import re
import time
from urllib.parse import parse_qs
from datetime import datetime, timedelta, timezone
import json

import jwt
from jinja2 import Environment, FileSystemLoader, select_autoescape
from passlib.hash import argon2
from watchdog_gevent import Observer
from werkzeug import Response

from volttron.utils.context import ClientContext
from volttron.utils.filewatch import VolttronHomeFileReloader
from volttron.utils.persistance import PersistentDict
from .token_revocation import (RevokedSessions, REVOKED_SESSIONS_FILE, SESSION_CLAIM, new_session_id,
                               session_id)

_log = logging.getLogger(__name__)

# Hash verified against when a login names an unknown user, so that the response time does not reveal which
# usernames exist. Generated once at import; the password is never accepted.
_UNKNOWN_USER_HASH = argon2.hash(os.urandom(32).hex())

__PACKAGE_DIR__ = os.path.dirname(os.path.abspath(__file__))
__TEMPLATE_DIR__ = os.path.join(__PACKAGE_DIR__, "templates")
__STATIC_DIR__ = os.path.join(__PACKAGE_DIR__, "static")


# Our admin interface will use Jinja2 templates based upon the above paths
# reference api for using Jinja2 http://jinja.pocoo.org/docs/2.10/api/
# Using the FileSystemLoader instead of the package loader in this case however.
tplenv = Environment(
    loader=FileSystemLoader(__TEMPLATE_DIR__),
    autoescape=select_autoescape(['html', 'xml'])
)


class AuthenticateEndpoints(object):

    def __init__(self, tls_private_key=None, tls_public_key=None, web_secret_key=None, revoked_sessions=None,
                 on_revoke=None):
        """
        :param revoked_sessions: the RevokedSessions deny-list to record revocations in. The web service shares
            its own so that every token check sees them; by default a list persisted in VOLTTRON_HOME is used.
        :param on_revoke: optional callable(session_id) run after a session is revoked, e.g. to close websockets.
        """

        self.refresh_token_timeout = 240  # minutes before token expires. TODO: Should this be a setting somewhere?
        self.access_token_timeout = 15  # minutes before token expires. TODO: Should this be a setting somewhere?
        self._tls_private_key = tls_private_key
        self._tls_public_key = tls_public_key
        self._web_secret_key = web_secret_key
        if self._tls_private_key is None and self._web_secret_key is None:
            raise ValueError("Must have either ssl_private_key or web_secret_key specified!")
        if self._tls_private_key is not None and self._web_secret_key is not None:
            raise ValueError("Must use either ssl_private_key or web_secret_key not both!")
        if revoked_sessions is None:
            revoked_sessions = RevokedSessions(os.path.join(ClientContext.get_volttron_home(),
                                                            REVOKED_SESSIONS_FILE))
        self._revoked_sessions = revoked_sessions
        self._on_revoke = on_revoke
        self._userdict = None
        self.reload_userdict()
        self._observer = Observer()
        self._observer.schedule(
            VolttronHomeFileReloader("web-users.json", self.reload_userdict),
            ClientContext.get_volttron_home()
        )
        self._observer.start()

    def reload_userdict(self):
        webuserpath = os.path.join(ClientContext.get_volttron_home(), 'web-users.json')
        self._userdict = PersistentDict(webuserpath)

    @property
    def revoked_sessions(self):
        return self._revoked_sessions

    def get_routes(self):
        """
        Returns a list of tuples with the routes for authentication.

        Tuple should have the following:

            - regular expression for calling the endpoint
            - 'callable' keyword specifying that a method is being specified
            - the method that should be used to call when the regular expression matches

        code:

            return [
                (re.compile('^/csr/request_new$'), 'callable', self._csr_request_new)
            ]

        :return:
        """
        return [
            (re.compile('^/authenticate'), 'callable', self.handle_authenticate)
        ]

    def handle_authenticate(self, env, data):
        """
        Callback for /authenticate endpoint.

        Routes request based on HTTP method and returns an application/json encoded token or error.

        :param env:
        :param data:
        :return: Response
        """
        method = env.get('REQUEST_METHOD')
        if method == 'POST':
            response = self.get_auth_tokens(env, data)
        elif method == 'PUT':
            response = self.renew_auth_token(env, data)
        elif method == 'DELETE':
            response = self.revoke_auth_token(env, data)
        else:
            error = f"/authenticate endpoint accepts only POST, PUT, or DELETE methods. Received: {method}"
            _log.warning(error)
            return Response(json.dumps({'error': error}), status=405, content_type='application/json')
        return response

    def get_auth_tokens(self, env, data):
        """
        Creates an authentication refresh and acccss tokens to be returned to the caller.  The
        response will be application/json encoded refresh and access tokens.  Data should contain:
        {
            "username": "<username>",
            "password": "<password>"
        }
        :param env:
        :param data:
        :return:
        """

        if len(self._userdict) == 0:
            # Users may have been added since startup (vctl web create-admin). The file watcher does not see the
            # atomic rename used by the writers, so refresh from disk before refusing.
            self.reload_userdict()
        if len(self._userdict) == 0:
            _log.error("No web users are configured. Create one with 'vctl web create-admin'.")
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')

        if not isinstance(data, dict):
            _log.debug("data is not a dict, decoding")
            decoded = dict((k, v if len(v) > 1 else v[0])
                           for k, v in parse_qs(data).items())

            username = decoded.get('username')
            password = decoded.get('password')

        else:
            username = data.get('username')
            password = data.get('password')

        error = ""
        if username is None:
            error += "Invalid username passed"
        if not password:
            error += "Invalid password passed"

        if error:
            _log.error("Invalid parameters passed: {}".format(error))
            return Response(json.dumps({'error': error}), status=401, content_type='application/json')

        user = self.__get_user(username, password)
        if user is None:
            _log.warning("Failed web login attempt from {}".format(env.get('REMOTE_ADDR')))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        access_token, refresh_token = self._get_tokens(user)
        response = Response(json.dumps({"refresh_token": refresh_token, "access_token": access_token}),
                            content_type="application/json")
        return response

    def _get_tokens(self, claims):
        # One session id per login; renewed access tokens inherit it from the refresh token, so revoking the
        # session revokes every token minted for it.
        if session_id(claims) is None:
            claims[SESSION_CLAIM] = new_session_id()
        now = datetime.now(timezone.utc)
        claims['iat'] = now
        claims['nbf'] = now
        claims['exp'] = now + timedelta(minutes=self.access_token_timeout)
        claims['grant_type'] = 'access_token'
        algorithm = 'RS256' if self._tls_private_key is not None else 'HS256'
        encode_key = self._tls_private_key if algorithm == 'RS256' else self._web_secret_key
        access_token = jwt.encode(claims, encode_key, algorithm=algorithm)
        claims['exp'] = now + timedelta(minutes=self.refresh_token_timeout)
        claims['grant_type'] = 'refresh_token'
        refresh_token = jwt.encode(claims, encode_key, algorithm=algorithm)
        # PyJWT 2.x encode returns str; 1.x returned bytes requiring .decode().
        # Ensure we always return str regardless of installed version.
        if isinstance(access_token, bytes):
            access_token = access_token.decode('utf-8')
        if isinstance(refresh_token, bytes):
            refresh_token = refresh_token.decode('utf-8')
        return access_token, refresh_token

    def renew_auth_token(self, env, data):
        """
        Creates a new authentication access token to be returned to the caller.  The
        response will be an application/json encoded access token.  Request should contain:
            • Content Type: application/json
            • Authorization: BEARER <jwt_refresh_token>
            • Body (optional):
                {
                "current_access_token": "<jwt_access_token>"
                }

        :param env:
        :param data:
        :return:
        """
        current_access_token = data.get('current_access_token')
        from ..web import get_bearer, get_user_claim_from_bearer, NotAuthorized
        try:
            current_refresh_token = get_bearer(env)
            claims = get_user_claim_from_bearer(current_refresh_token, web_secret_key=self._web_secret_key,
                                                tls_public_key=self._tls_public_key)
        except NotAuthorized:
            _log.error("Unauthorized user attempted to connect to {}".format(env.get('PATH_INFO')))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')

        except jwt.ExpiredSignatureError:
            _log.error("User attempted to connect to {} with an expired signature".format(env.get('PATH_INFO')))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')

        except jwt.PyJWTError:
            # Catches tampered-algorithm tokens and other PyJWT 2.x decode failures
            # (e.g. InvalidAlgorithmError, DecodeError) that are not covered by the
            # specific subclass handlers above. Return a clean 401 rather than a 500.
            _log.error("JWT decode error for request to {}".format(env.get('PATH_INFO')))
            return Response('Unauthorized User', status="401 Unauthorized")

        if claims.get('grant_type') != 'refresh_token' or not claims.get('groups'):
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        if not self._revoked_sessions.allows(claims):
            _log.warning("Refresh attempted with a revoked or unrevocable token at {}".format(env.get('PATH_INFO')))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        # TODO: Consider blacklisting and reissuing refresh tokens also when used.
        new_access_token, _ = self._get_tokens(claims)
        if current_access_token:
            pass  # TODO: keep current subscriptions? blacklist old token?
        return Response(json.dumps({"access_token": new_access_token}), content_type="application/json")

    def revoke_auth_token(self, env, data):
        """
        Revokes the login session of the presented token (logout).  Request should contain:
            • Authorization: BEARER <jwt_access_token or jwt_refresh_token>

        Every token minted for that login - the access token, the refresh token and any access token renewed
        from it - is refused from then on, and websockets opened with them are closed. The token is read from
        the Authorization header only, never the cookie, so a request made by another site cannot log the
        user out.

        :return: 204 when the session is revoked (also when it already was); 401 when no valid token of this
            server is presented.
        """
        from ..web import get_authorization_bearer, get_user_claim_from_bearer
        path = env.get('PATH_INFO')
        bearer = get_authorization_bearer(env)
        if not bearer:
            _log.error("Revocation request to {} without a bearer Authorization header".format(path))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        try:
            claims = get_user_claim_from_bearer(bearer, web_secret_key=self._web_secret_key,
                                                tls_public_key=self._tls_public_key)
        except jwt.PyJWTError as err:
            _log.error("Revocation request to {} with a token that does not validate: {}".format(
                path, type(err).__name__))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        sid = session_id(claims)
        if claims.get('grant_type') not in ('access_token', 'refresh_token') or sid is None:
            _log.error("Revocation request to {} with a token that is not a session token".format(path))
            return Response(json.dumps({'error': 'Not Authorized'}), status=401, content_type='application/json')
        self._revoked_sessions.revoke(sid, self._session_end(claims))
        _log.info("Web session revoked.")
        if self._on_revoke is not None:
            try:
                self._on_revoke(sid)
            except Exception as err:
                # The deny-list is already written; a cleanup failure must not look like a failed logout.
                _log.error("Post-revocation cleanup failed: %s", type(err).__name__)
        return Response(status=204)

    def _session_end(self, claims):
        """Latest moment any token of the session can still be valid.

        The refresh token lives refresh_token_timeout past the login that minted it, and an access token renewed
        just before that lives access_token_timeout longer. The ``iat`` of any token of the session is at or
        after the login, so this is an upper bound whichever token was presented.
        """
        now = time.time()
        issued = claims.get('iat')
        if not isinstance(issued, (int, float)) or isinstance(issued, bool):
            issued = now
        return max(issued, now) + (self.refresh_token_timeout + self.access_token_timeout) * 60

    def __get_user(self, username, password):
        """
        Retrieve user from the user store based upon username/password

        The hashed_password will not be returned with the value in the user
        object.

        If there is not a username/password that match return None.

        :param username:
        :param password:
        :return:
        """
        user = self._userdict.get(username)
        if user is None:
            # The user may have been created since the dictionary was last loaded; the file watcher misses the
            # atomic rename performed by the writers, so look once more before deciding.
            self.reload_userdict()
            user = self._userdict.get(username)
        if user is not None:
            hashed_pass = user.get('hashed_password')
            if hashed_pass and argon2.verify(password, hashed_pass):
                usr_cpy = user.copy()
                del usr_cpy['hashed_password']
                return usr_cpy
            return None
        # Unknown user: spend the same argon2 work as a real verification so timing does not leak usernames.
        argon2.verify(password, _UNKNOWN_USER_HASH)
        return None

