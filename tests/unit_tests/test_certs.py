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

import json
import os
import pytest

from pathlib import Path
from volttron.utils.certs import Certs
from volttron.utils.messagebus import store_message_bus_config

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ
from volttrontesting.certs_utils import TLSRepository

try:
    import openssl
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

INSTANCE_NAME = "VC"
PLATFORM_CONFIG = """
#host parameter is mandatory parameter. fully qualified domain name
host: mymachine.pnl.gov

# mandatory. certificate data used to create root ca certificate. Each volttron
# instance must have unique common-name for root ca certificate
certificate-data:
  country: 'US'
  state: 'Washington'
  location: 'Richland'
  organization: 'PNNL'
  organization-unit: 'VOLTTRON Team'
  # volttron_instance has to be replaced with actual instance name of the VOLTTRON
  common-name: 'volttron_instance_root_ca'
# certificate data could also point to existing public and private key files
# of a CA. In that case, use the below certificate-data parameters instead of
# the above. Note. public and private should be pem encoded and use rsa
#  encryption
#
#certificate-data:
#  ca-public-key: /path/to/ca/public/key/ca_pub.crt
#  ca-private-key: /path/to/ca/private/key/ca_private.pem


#
# optional parameters for single instance setup
#
virtual-host: 'volttron' #defaults to volttron

# use the below four port variables if using custom rabbitmq ports
# defaults to 5672
amqp-port: '5672'

# defaults to 5671
amqp-port-ssl: '5671'

# defaults to 15672
mgmt-port: '15672'

# defaults to 15671
mgmt-port-ssl: '15671'

# defaults to true
ssl: 'true'

# defaults to ~/rabbitmq_server/rabbbitmq_server-3.9.7
rmq-home: "~/rabbitmq_server/rabbitmq_server-3.9.7"
"""


def _temp_csr(volttron_home):
    """
        Create a Certificate Signing Request (CSR) using the Certs class.
        Use this CSR to test approving, denying, and deleting CSRs
        """
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        certs = Certs()
        data = {'C': 'US',
                'ST': 'Washington',
                'L': 'Richland',
                'O': 'pnnl',
                'OU': 'volttron',
                'CN': INSTANCE_NAME + "_root_ca"}
        certs.create_root_ca(**data)
        assert certs.ca_exists()

        certs.create_signed_cert_files(name="FullyQualifiedIdentity", ca_name=certs.root_ca_name)

        csr = certs.create_csr("FullyQualifiedIdentity", "RemoteInstanceName")
        return certs, csr


def test_certificate_directories():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        certs = Certs()
        paths = (certs.certs_pending_dir, certs.private_dir, certs.cert_dir,
                 certs.remote_cert_dir, certs.csr_pending_dir, certs.ca_db_dir)

        for p in paths:
            assert os.path.exists(p)


@pytest.mark.skipif(not HAS_OPENSSL, reason="Requires openssl")
def test_create_root_ca():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        certs = Certs()
        assert not certs.ca_exists()
        data = {'C': 'US',
                'ST': 'Washington',
                'L': 'Richland',
                'O': 'pnnl',
                'OU': 'volttron',
                'CN': INSTANCE_NAME+"_root_ca"}
        certs.create_root_ca(**data)
        assert certs.ca_exists()

        private_key = certs.private_key_file("VC-root-ca")
        cert_file = certs.cert_file("VC-root-ca")
        tls = TLSRepository(repo_dir=volttron_home, openssl_cnffile="openssl.cnf", serverhost="FullyQualifiedIdentity")
        assert tls.verify_ca_cert(private_key, cert_file)


def test_create_signed_cert_files():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        certs = Certs()
        assert not certs.cert_exists("test_cert")

        data = {'C': 'US',
                'ST': 'Washington',
                'L': 'Richland',
                'O': 'pnnl',
                'OU': 'volttron',
                'CN': INSTANCE_NAME+"_root_ca"}
        certs.create_root_ca(**data)
        assert certs.ca_exists()

        certs.create_signed_cert_files("test_cert")
        assert certs.cert_exists("test_cert")

        existing_cert = certs.create_signed_cert_files("test_cert")
        assert existing_cert[0] == certs.cert("test_cert")


@pytest.mark.skipif(not HAS_OPENSSL, reason="Requires openssl")
def test_create_csr():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        # Use TLS repo to create a CA
        tls = TLSRepository(repo_dir=volttron_home, openssl_cnffile="openssl.cnf",
                            serverhost="FullyQualifiedIdentity")
        tls.__create_ca__()
        certs_using_tls = Certs(volttron_home)

        assert certs_using_tls.cert_exists("VC-root-ca")
        assert Path(certs_using_tls.cert_file("VC-root-ca")) == tls._ca_cert

        # Create Volttron CSR using TLS repo CA
        csr = certs_using_tls.create_csr("FullyQualifiedIdentity", "RemoteInstanceName")

        # Write CSR to a file to verify
        csr_file_path = os.path.join(certs_using_tls.cert_dir, "CSR.csr")
        csr_private_key_path = certs_using_tls.private_key_file("FullyQualifiedIdentity")
        with open(csr_file_path, "wb") as f:
            f.write(csr)

        csr_info = tls.verify_csr(csr_file_path, csr_private_key_path)
        assert csr_info != None


def test_approve_csr():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        certs, csr = _temp_csr(volttron_home)

        # Save pending CSR request into a CSR file
        csr_file = certs.save_pending_csr_request("10.1.1.1", "test_csr", csr)
        f = open(csr_file, "rb")
        assert f.read() == csr
        f.close()

        # Check meta data saved in file for CSR
        csr_meta_file = os.path.join(certs.csr_pending_dir, "test_csr.json")
        f = open(csr_meta_file, "r")
        data = f.read()
        csr_meta_data = json.loads(data)
        f.close()
        assert csr_meta_data['status'] == "PENDING"
        assert csr_meta_data['csr'] == csr.decode("utf-8")

        # Approve the CSR
        signed_cert = certs.approve_csr("test_csr")
        f = open(csr_meta_file, "r")
        updated_data = f.read()
        approved_csr_meta_data = json.loads(updated_data)
        f.close()
        assert approved_csr_meta_data['status'] == "APPROVED"


def test_deny_csr():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        certs, csr = _temp_csr(volttron_home)

        # Save pending CSR request into a CSR file
        csr_file = certs.save_pending_csr_request("10.1.1.1", "test_csr", csr)
        f = open(csr_file, "rb")
        assert f.read() == csr
        f.close()

        # Check meta data saved in file for CSR
        csr_meta_file = os.path.join(certs.csr_pending_dir, "test_csr.json")
        f = open(csr_meta_file, "r")
        data = f.read()
        csr_meta_data = json.loads(data)
        f.close()
        assert csr_meta_data['status'] == "PENDING"
        assert csr_meta_data['csr'] == csr.decode("utf-8")

        # Deny the CSR
        certs.deny_csr("test_csr")
        f = open(csr_meta_file, "r")
        updated_data = f.read()
        denied_csr_meta_data = json.loads(updated_data)
        f.close()
    
        # Check that the CSR was denied, the pending CSR files still exist, and the cert has been removed
        assert denied_csr_meta_data['status'] == "DENIED"
        assert os.path.exists(csr_meta_file)
        assert os.path.exists(csr_file)
        assert certs.cert_exists("test_csr") == False


def test_delete_csr():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        certs, csr = _temp_csr(volttron_home)

        # Save pending CSR request into a CSR file
        csr_file = certs.save_pending_csr_request("10.1.1.1", "test_csr", csr)
        f = open(csr_file, "rb")
        assert f.read() == csr
        f.close()

        # Check meta data saved in file for CSR
        csr_meta_file = os.path.join(certs.csr_pending_dir, "test_csr.json")
        f = open(csr_meta_file, "r")
        data = f.read()
        csr_meta_data = json.loads(data)
        f.close()
        assert csr_meta_data['status'] == "PENDING"
        assert csr_meta_data['csr'] == csr.decode("utf-8")

        # Delete CSR
        certs.delete_csr("test_csr")

        # Check that the CSR files have been deleted and the cert has been removed
        assert os.path.exists(csr_meta_file) == False
        assert os.path.exists(csr_file) == False
        assert certs.cert_exists("test_csr") == False


# def test_cadb_updated(temp_volttron_home):
#     certs = Certs()
#     certs.create_root_ca()
#     instance_name = ClientContext.get_instance_name(False)
#     assert not os.path.exists(certs.ca_db_file(instance_name))
#     certs.create_instance_ca(instance_name)
#     assert os.path.exists(certs.ca_db_file(instance_name))
#
#
# def test_create_instance_ca(temp_volttron_home):
#     certs = Certs()
#     certs.create_root_ca()
#     instance_name = ClientContext.get_instance_name(False)
#     assert instance_name == INSTANCE_NAME
#     assert not certs.cert_exists(instance_name)
#     certs.create_instance_ca(instance_name)
#     assert certs.cert_exists(instance_name)
#     assert certs.verify_cert(instance_name)
