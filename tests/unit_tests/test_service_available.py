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

"""The platform loads services through the ``@service`` registry; the web service must be registered there."""
from volttron.client.known_identities import PLATFORM_WEB
from volttron.server.decorators import service

# Importing the module performs the registration.
from volttron.services.web.platform_web_service import PlatformWebService


def test_web_service_registered():
    assert service.registry.get(PLATFORM_WEB) is PlatformWebService
    assert PlatformWebService.Meta.identity == PLATFORM_WEB
