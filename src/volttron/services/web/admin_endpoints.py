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
import re

from volttron.client.known_identities import PLATFORM_WEB

try:
    from jinja2 import TemplateNotFound
except ImportError:
    logging.getLogger().warning("Missing jinja2 library in admin_endpoints.py")

from werkzeug import Response


_log = logging.getLogger(__name__)


def template_env(env):
    return env['JINJA2_TEMPLATE_ENV']


class AdminEndpoints(object):
    """
    Serves the /admin pages of the platform web service.

    Web users are managed with ``vctl web`` (see :mod:`volttron.services.web.user_manager`); this class does not
    create or modify users. The login page is served to anyone; every other page requires a bearer token (header
    or ``Bearer`` cookie) whose claims include the ``admin`` group.
    """

    def __init__(self, ssl_public_key: bytes = None, rpc_caller=None):

        self._rpc_caller = rpc_caller

        if ssl_public_key is None:
            self._insecure_mode = True
        else:
            self._insecure_mode = False

        # must have a none value for when we don't have an ssl context available.
        if ssl_public_key is not None:
            if isinstance(ssl_public_key, bytes):
                self._ssl_public_key = ssl_public_key.decode('utf-8')
            elif isinstance(ssl_public_key, str):
                self._ssl_public_key = ssl_public_key

            else:
                raise ValueError("Invalid type for ssl_public_key")
        else:
            self._ssl_public_key = None

    def get_routes(self):
        """
        Returns a list of tuples with the routes for the administration endpoints
        available in it.

        :return:
        """
        return [
            (re.compile('^/admin.*'), 'callable', self.admin)
        ]

    def admin(self, env, data):
        if 'login.html' in env.get('PATH_INFO') or '/admin/' == env.get('PATH_INFO'):
            template = template_env(env).get_template('login.html')
            _log.debug("Login.html: {}".format(env.get('PATH_INFO')))
            return Response(template.render(), content_type='text/html')

        return self.verify_and_dispatch(env, data)

    @staticmethod
    def _unauthorized():
        return Response('<h1>Unauthorized User</h1>', status="401 Unauthorized")

    def verify_and_dispatch(self, env, data):
        """ Verify that the user is an admin and dispatch

        :param env: web environment
        :param data: data associated with a web form or json/xml request data
        :return: Response object.
        """
        from ..web import get_bearer, NotAuthorized
        path_info = env.get('PATH_INFO')
        try:
            bearer = get_bearer(env)
            if not bearer:
                raise NotAuthorized("No bearer token supplied.")
            claims = self._rpc_caller(PLATFORM_WEB, 'get_user_claims', bearer).get() or {}
        except NotAuthorized:
            _log.warning("Unauthorized user attempted to connect to {}".format(path_info))
            return self._unauthorized()
        except Exception as e:
            # Expired, tampered or otherwise undecodable tokens all arrive here as RemoteErrors from the web service.
            # Every failure is treated the same way: the request is refused. The login page will re-authenticate.
            _log.warning("Rejected token for {}: {}".format(path_info, e.__class__.__name__))
            if 'ExpiredSignatureError' in str(getattr(e, 'exc_info', {}).get('exc_type', '')):
                template = template_env(env).get_template('login.html')
                return Response(template.render(), content_type='text/html')
            return self._unauthorized()

        # Make sure we have only admins for viewing this.
        if 'admin' not in (claims.get('groups') or []):
            return self._unauthorized()

        if path_info.endswith('html'):
            page = path_info.split('/')[-1]
            try:
                template = template_env(env).get_template(page)
            except TemplateNotFound:
                return Response("<h1>404 Not Found</h1>", status="404 Not Found")
            return Response(template.render(), content_type="text/html")

        template = template_env(env).get_template('index.html')
        resp = template.render()
        return Response(resp)
