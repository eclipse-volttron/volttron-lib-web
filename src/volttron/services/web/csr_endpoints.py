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

import re
import logging
import weakref

from werkzeug import Response

from volttron.utils import jsonapi
from volttron.utils.certs import Certs
from volttron.utils.context import ClientContext

_log = logging.getLogger(__name__)


class CSREndpoints(object):

    def __init__(self, core):
        self._core = weakref.ref(core)
        self._certs = Certs()
        self._auto_allow_csr = False

    @property
    def auto_allow_csr(self):
        return self._auto_allow_csr

    @auto_allow_csr.setter
    def auto_allow_csr(self, value):
        self._auto_allow_csr = value

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
            (re.compile('^/csr/request_new$'), 'callable', self._csr_request_new)
        ]

    def _csr_request_new(self, env, data):
        _log.debug("New csr request")
        if not isinstance(data, dict):
            try:
                request_data = jsonapi.loads(data)
            except:
                _log.error("Invalid data for csr request.  Must be json serializable")
                return Response()
        else:
            request_data = data.copy()

        csr = request_data.get('csr').encode("utf-8")
        identity = self._certs.get_csr_common_name(csr)

        # The identity must start with the current instances name or it is a failure.
        if not identity.startswith(ClientContext.get_instance_name() + "."):
            json_response = dict(status="ERROR",
                                 message="CSR must start with instance name: {}".format(
                                     ClientContext.get_instance_name()))
            Response(jsonapi.dumps(json_response),
                     content_type='application/json',
                     headers={'Content-type': 'application/json'})

        csr_file = self._certs.save_pending_csr_request(env.get('REMOTE_ADDR'), identity, csr)

        if self._auto_allow_csr:
            _log.debug("Creating cert and permissions for user: {}".format(identity))
            status = self._certs.get_csr_status(identity)
            json_response = dict(status=status)
            if status == 'APPROVED':
                try:
                    json_response['cert'] = self._certs.get_cert_from_csr(identity)
                except Exception as e:
                    _log.error(f"Exception getting cert from csr {e}")

            else:
                try:
                    cert = self._certs.approve_csr(identity)
                    #permissions = self._core().rmq_mgmt.get_default_permissions(identity)
                    _log.debug(f"CREATING NEW RMQ USER: {identity}")
                    permissions = dict(configure=".*", read=".*",
                                       write=".*")
                    self._core().rmq_mgmt.create_user_with_permissions(identity,
                                                                       permissions,
                                                                       True)
                    json_response = dict(
                        status="SUCCESSFUL",
                        cert=cert
                    )
                except BaseException as e:
                    _log.error(f"Exception in approving csr/creating user in auto_allow_csr mode: {e}")
        else:

            status = self._certs.get_csr_status(identity)
            cert = self._certs.get_cert_from_csr(identity)

            json_response = dict(status=status)
            if status == "APPROVED":
                json_response['cert'] = self._certs.get_cert_from_csr(identity)
            elif status == "PENDING":
                json_response['message'] = "The request is pending admininstrator approval."
            elif status == "DENIED":
                json_response['message'] = "The request has been denied by the administrator."
            elif status == "UNKNOWN":
                json_response['message'] = "An unknown common name was specified to the server {}".format(identity)
            else:
                json_response['message'] = "An unkonwn error has occured during the respons phase"

        response = None
        try:
            if json_response.get('cert', None):
                json_response['cert'] = json_response['cert'].decode('utf-8')
            response = Response(jsonapi.dumps(json_response),
                     content_type='application/json',
                     headers={'Content-type': 'application/json'})
        except BaseException as e:
            _log.error(f"Exception creating Response {e}")
        return response
