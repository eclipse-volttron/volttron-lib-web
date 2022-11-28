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
import requests
from urllib.parse import urlparse, urljoin

from volttron.utils import jsonapi
from volttron.utils.certs import Certs

_log = logging.getLogger(__name__)


class DiscoveryError(Exception):
    """ Raised when a different volttron central tries to register.
    """
    pass


class DiscoveryInfo(object):
    """ A DiscoveryInfo class.

    The DiscoveryInfo class provides a wrapper around the return values from
    a call to the /discovery/ endpoint of the `volttron.services.web.
    """

    def __init__(self, **kwargs):

        self.discovery_address = kwargs.pop('discovery_address')
        self.vip_address = kwargs.pop('vip-address', None)
        self.serverkey = kwargs.pop('serverkey', None)
        self.instance_name = kwargs.pop('instance-name')
        try:
            self.rmq_address = kwargs.pop('rmq-address')
        except KeyError:
            self.messagebus_type = 'zmq'
        else:
            self.messagebus_type = 'rmq'
        try:
            self.rmq_ca_cert = kwargs.pop('rmq-ca-cert')
        except KeyError:
            self.messagebus_type = 'zmq'
        else:
            self.messagebus_type = 'rmq'
        self.certs = Certs()

        assert len(kwargs) == 0

    @staticmethod
    def request_discovery_info(web_address):
        """  Construct a `DiscoveryInfo` object.

        Requests a response from discovery_address and constructs a
        `DiscoveryInfo` object with the returned json.

        :param web_address: An http(s) address with volttron running.
        :return:
        """

        try:
            parsed = urlparse(web_address)

            assert parsed.scheme
            assert not parsed.path

            real_url = urljoin(web_address, "/discovery/")
            _log.info('Connecting to: {}'.format(real_url))
            response = requests.get(real_url, verify=False)

            if not response.ok:
                raise DiscoveryError(
                    "Invalid discovery response from {}".format(real_url)
                )
        except AttributeError as e:
            raise DiscoveryError(
                "Invalid web_address passed {}"
                .format(web_address)
            )
        except requests.exceptions.RequestException as e:
            raise DiscoveryError(
                "Connection to {} not available".format(real_url)
            )
        except Exception as e:
            raise DiscoveryError("Unhandled exception {}".format(e))

        return DiscoveryInfo(
            discovery_address=web_address, **(response.json()))

    def __str__(self):
        dk = {
            'discovery_address': self.discovery_address,
            'instance_name': self.instance_name,
            'messagebus_type': self.messagebus_type
        }
        if self.messagebus_type == 'rmq':
            dk['rmq_address'] = self.rmq_address
            dk['rmq_ca_cert'] = self.rmq_ca_cert

        if self.vip_address:
            dk['vip_address'] = self.vip_address
            dk['serverkey'] = self.serverkey

        return jsonapi.dumps(dk)
