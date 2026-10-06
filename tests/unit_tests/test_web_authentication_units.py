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

import gevent
import json
import jwt
import os
import pytest

from deepdiff import DeepDiff
from urllib.parse import urlencode

from volttron.services.web import get_user_claim_from_bearer
from volttron.services.web.admin_endpoints import AdminEndpoints
from volttron.services.web.authenticate_endpoint import AuthenticateEndpoints
from volttron.utils.certs import CertWrapper
from volttron.utils.messagebus import store_message_bus_config

from volttrontesting.fixtures.cert_fixtures import certs_profile_1

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ
from web_utils import get_test_web_env

def get_random_key(length: int = 65) -> str:
    """
    Returns a hex random key of specified length.  The length must be > 0 in order for
    the key to be valid.  Raises a ValueError if the length is invalid.

    The default length is 65, which is 130 in length when hexlify is run.

    :param length:
    :return:
    """
    if length <= 0:
        raise ValueError("Invalid length specified for random key must be > 0")

    import binascii

    random_key = binascii.hexlify(os.urandom(length)).decode("utf-8")
    return random_key

@pytest.mark.parametrize("encryption_type", ("private_key", "tls"))
def test_jwt_encode(encryption_type):
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        store_message_bus_config('', 'my_instance_name')
        if encryption_type == "private_key":
            algorithm = "HS256"
            encoded_key = get_random_key().encode("utf-8")
        else:
            with certs_profile_1(volttron_home) as certs:
                algorithm = "RS256"
                encoded_key = CertWrapper.get_private_key(certs.server_certs[0].key_file)
        claims = {"woot": ["bah"], "all I want": 3210, "do it next": {"foo": "billy"}}
        token = jwt.encode(claims, encoded_key, algorithm)
        if encryption_type == 'tls':
            decode_key = CertWrapper.get_cert_public_key(certs.server_certs[0].cert_file)
            new_claims = jwt.decode(token, decode_key, algorithms=[algorithm])
        else:
            new_claims = jwt.decode(token, encoded_key, algorithms=[algorithm])

        assert not DeepDiff(claims, new_claims)


# Child of AuthenticateEndpoints.
# Exactly the same but includes helper methods to set access and refresh token timeouts
class MockAuthenticateEndpoints(AuthenticateEndpoints):
    def set_refresh_token_timeout(self, timeout):
        self.refresh_token_timeout = timeout

    def set_access_token_timeout(self, timeout):
        self.access_token_timeout = timeout


# Setup test values for authenticate tests
def set_test_admin():
    authorize_ep = MockAuthenticateEndpoints(web_secret_key=get_random_key())
    authorize_ep.set_access_token_timeout(0.1)
    authorize_ep.set_refresh_token_timeout(0.2)
    AdminEndpoints().add_user("test_admin", "Pass123", groups=['admin'])
    test_user = {"username": "test_admin", "password": "Pass123"}
    gevent.sleep(1)
    return authorize_ep, test_user


def test_authenticate_get_request_fails():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        env = get_test_web_env('/authenticate', method='GET')
        response = authorize_ep.handle_authenticate(env, test_user)
        assert ('Content-Type', 'application/json') in response.headers.items()
        assert '405 METHOD NOT ALLOWED' in response.status

def test_authenticate_post_request():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        env = get_test_web_env('/authenticate', method='POST')
        response = authorize_ep.handle_authenticate(env, test_user)
        assert ('Content-Type', 'application/json') in response.headers.items()
        assert '200 OK' in response.status
        response_token = json.loads(response.response[0].decode('utf-8'))
        refresh_token = response_token['refresh_token']
        access_token = response_token["access_token"]
        assert 3 == len(refresh_token.split('.'))
        assert 3 == len(access_token.split("."))


def test_authenticate_put_request():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        # Get tokens for test
        env = get_test_web_env('/authenticate', method='POST')
        response = authorize_ep.handle_authenticate(env, test_user)
        response_token = json.loads(response.response[0].decode('utf-8'))
        refresh_token = response_token['refresh_token']
        access_token = response_token["access_token"]

        # Test PUT Request
        env = get_test_web_env('/authenticate', method='PUT')
        env["HTTP_AUTHORIZATION"] = "BEARER " + refresh_token
        response = authorize_ep.handle_authenticate(env, data={})
        assert ('Content-Type', 'application/json') in response.headers.items()
        assert '200 OK' in response.status


def test_authenticate_put_request_access_expires():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        # Get tokens for test
        env = get_test_web_env('/authenticate', method='POST')
        response = authorize_ep.handle_authenticate(env, test_user)
        response_token = json.loads(response.response[0].decode('utf-8'))
        refresh_token = response_token['refresh_token']
        access_token = response_token["access_token"]

        # Get access token after previous token expires. Verify they are different
        gevent.sleep(7)
        env = get_test_web_env('/authenticate', method='PUT')
        env["HTTP_AUTHORIZATION"] = "BEARER " + refresh_token
        response = authorize_ep.handle_authenticate(env, data={})
        assert ('Content-Type', 'application/json') in response.headers.items()
        assert '200 OK' in response.status
        assert access_token != json.loads(response.response[0].decode('utf-8'))["access_token"]


def test_authenticate_put_request_refresh_expires():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        # Get tokens for test
        env = get_test_web_env('/authenticate', method='POST')
        response = authorize_ep.handle_authenticate(env, test_user)
        response_token = json.loads(response.response[0].decode('utf-8'))
        refresh_token = response_token['refresh_token']
        access_token = response_token["access_token"]

        # Wait for refresh token to expire
        gevent.sleep(20)
        env = get_test_web_env('/authenticate', method='PUT')
        env["HTTP_AUTHORIZATION"] = "BEARER " + refresh_token
        response = authorize_ep.handle_authenticate(env, data={})
        assert ('Content-Type', 'application/json') in list(response.headers.items())
        assert "401 UNAUTHORIZED" in response.status


def test_authenticate_delete_request():
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        authorize_ep, test_user = set_test_admin()
        # Get tokens for test
        env = get_test_web_env('/authenticate', method='POST')
        response = authorize_ep.handle_authenticate(env, test_user)

        # Touch Delete endpoint
        env = get_test_web_env('/authenticate', method='DELETE')
        response = authorize_ep.handle_authenticate(env, test_user)
        assert ('Content-Type', 'application/json') in response.headers.items()
        assert '501 NOT IMPLEMENTED' in response.status


def test_no_private_key_or_passphrase():
    with pytest.raises(ValueError,
                       match="Must have either ssl_private_key or web_secret_key specified!"):
        AuthenticateEndpoints()


def test_both_private_key_and_passphrase():
    with pytest.raises(ValueError,
                       match="Must use either ssl_private_key or web_secret_key not both!"):
        volttron_home = create_volttron_home()
        with with_os_environ({'VOLTTRON_HOME': volttron_home}):
            store_message_bus_config('', 'my_instance_name')
            with certs_profile_1(f'{volttron_home}/certificates') as certs:
                AuthenticateEndpoints(web_secret_key=get_random_key(), tls_private_key=certs.server_certs[0].key)


@pytest.mark.parametrize("scheme", ("http", "https"))
def test_authenticate_endpoint(scheme):
    kwargs = {}

    # Note this is not a context wrapper, it just does the creation for us
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
        if scheme == 'https':
            with certs_profile_1(volttron_home) as certs:
                kwargs['web_ssl_key'] = certs.server_certs[0].key_file
                kwargs['web_ssl_cert'] = certs.server_certs[0].cert_file
        else:
            kwargs['web_secret_key'] = get_random_key()
        # TODO: Save kwargs to service_config.yml
        user = 'bogart'
        passwd = 'cat'
        adminep = AdminEndpoints()
        adminep.add_user(user, passwd)

        env = get_test_web_env('/authenticate', method='POST')

        if scheme == 'http':
            authorizeep = AuthenticateEndpoints(web_secret_key=kwargs.get('web_secret_key'))
        else:
            authorizeep = AuthenticateEndpoints(tls_private_key=CertWrapper.load_key(kwargs.get('web_ssl_key')))

        invalid_login_username_params = dict(username='fooey', password=passwd)

        response = authorizeep.get_auth_tokens(env, invalid_login_username_params)

        # assert '401 Unauthorized' in response.content
        assert '401 UNAUTHORIZED' == response.status

        invalid_login_password_params = dict(username=user, password='hazzah')
        response = authorizeep.get_auth_tokens(env, invalid_login_password_params)

        assert '401 UNAUTHORIZED' == response.status
        valid_login_params = urlencode(dict(username=user, password=passwd))
        response = authorizeep.get_auth_tokens(env, valid_login_params)
        assert '200 OK' == response.status
        assert "application/json" in response.content_type
        response_data = json.loads(response.data.decode('utf-8'))
        assert 3 == len(response_data["refresh_token"].split('.'))
        assert 3 == len(response_data["access_token"].split('.'))



# ---------------------------------------------------------------------------
# VO-003 algorithm-enforcement tests (no platform fixture required)
# ---------------------------------------------------------------------------

# These tests call PyJWT directly to manufacture good and bad tokens, then
# verify that get_user_claim_from_bearer (the VO-003-hardened decode site)
# enforces the algorithm list.  The RS256 tests require the cryptography
# package; they are skipped (not xfailed) when keygen fails so the gap is
# visible in CI without masking the HS256 coverage.

def _rs256_keypair():
    """
    Generate a fresh RSA 2048-bit keypair via cryptography.
    Returns (private_key_obj, public_key_pem_str).
    Raises ImportError if the cryptography package is unavailable.
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def test_vo003_alg_none_token_is_rejected():
    """
    A token with alg=none (unsigned) MUST be rejected.

    PyJWT 2.x refuses to decode an alg=none token unless 'none' is in the
    algorithms list.  get_user_claim_from_bearer passes algorithms=['HS256']
    so the decode raises a PyJWT error.  Verify the call raises, not returns
    claims, and that the exception is a jwt.PyJWTError subclass (not a raw
    Python exception that would surface as a 500).
    """
    secret = get_random_key()

    # Build a minimal alg=none token by hand: header, payload, empty sig.
    import base64

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "attacker", "groups": ["admin"]}).encode())
    none_token = f"{header}.{payload}."

    with pytest.raises(jwt.PyJWTError):
        get_user_claim_from_bearer(none_token, web_secret_key=secret)


def test_vo003_hs256_token_with_wrong_secret_is_rejected():
    """
    A token signed HS256 with a DIFFERENT secret MUST be rejected.

    This covers the signature-verification path: a token issued by an
    attacker using a different HS256 secret is not accepted.
    """
    legitimate_secret = get_random_key()
    attacker_secret = get_random_key()

    claims = {"sub": "attacker", "groups": ["admin"]}
    attacker_token = jwt.encode(claims, attacker_secret, algorithm="HS256")
    if isinstance(attacker_token, bytes):
        attacker_token = attacker_token.decode("utf-8")

    with pytest.raises(jwt.PyJWTError):
        get_user_claim_from_bearer(attacker_token, web_secret_key=legitimate_secret)


def test_vo003_hs256_alg_confusion_rejected():
    """
    Public-key-as-HMAC confusion: the algorithm-list enforcement at the
    RS256 decode site MUST reject any token whose header declares 'HS256'
    when the configured algorithms allow only 'RS256'.

    PyJWT 2.x refuses to sign HS256 with a PEM key (InvalidKeyError), so we
    construct the confused token by hand (base64url-encoded header + payload
    + empty signature) to verify the DECODE-side guard independently of the
    ENCODE-side guard.  The fix at the decode site uses algorithms=['RS256'];
    a token header declaring 'HS256' must raise a jwt.PyJWTError subclass
    rather than returning claims.
    """
    pytest.importorskip("cryptography", reason="cryptography package required for RS256 keygen")
    try:
        private_key, public_pem = _rs256_keypair()
    except Exception as exc:
        pytest.skip(f"RS256 keygen unavailable on this toolchain: {exc}")

    import base64

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    # Craft a token with alg=HS256 in the header but an empty/invalid sig.
    # Even if the signature were valid HS256, the decode must reject it because
    # the configured algorithms list contains only 'RS256'.
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"sub": "attacker", "groups": ["admin"]}).encode())
    confused_token = f"{header}.{payload}."

    with pytest.raises(jwt.PyJWTError):
        get_user_claim_from_bearer(confused_token, tls_public_key=public_pem)


def test_vo003_valid_hs256_token_accepted():
    """
    Allow side: a legitimately HS256-signed token with the correct secret
    MUST verify and return the expected claims.

    Asserts field values per data-invariants Rule 1, not just non-crash.
    """
    secret = get_random_key()
    original_claims = {"sub": "bob", "groups": ["admin"], "grant_type": "access_token"}
    token = jwt.encode(original_claims, secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    decoded = get_user_claim_from_bearer(token, web_secret_key=secret)

    assert decoded["sub"] == "bob"
    assert decoded["groups"] == ["admin"]
    assert decoded["grant_type"] == "access_token"


def test_vo003_valid_rs256_token_accepted():
    """
    Allow side: a legitimately RS256-signed token verified with the matching
    public key MUST verify and return the expected claims.

    Asserts field values per data-invariants Rule 1.
    Skipped if RS256 keygen is unavailable on this toolchain.
    """
    pytest.importorskip("cryptography", reason="cryptography package required for RS256 keygen")
    try:
        private_key, public_pem = _rs256_keypair()
    except Exception as exc:
        pytest.skip(f"RS256 keygen unavailable on this toolchain: {exc}")

    original_claims = {"sub": "alice", "groups": ["operator"], "grant_type": "access_token"}
    token = jwt.encode(original_claims, private_key, algorithm="RS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")

    decoded = get_user_claim_from_bearer(token, tls_public_key=public_pem)

    assert decoded["sub"] == "alice"
    assert decoded["groups"] == ["operator"]
    assert decoded["grant_type"] == "access_token"


def test_vo003_jwt_encode_returns_str():
    """
    PyJWT 2.x encode returns str; 1.x returned bytes.

    Assert that jwt.encode returns a str (not bytes) and that the token
    round-trips through decode without requiring a .decode() call.
    This verifies the str-return contract the VO-003 fix relies on.
    """
    secret = get_random_key()
    claims = {"sub": "carol", "groups": ["viewer"]}

    token = jwt.encode(claims, secret, algorithm="HS256")

    # Under PyJWT 2.x the return type MUST be str.
    assert isinstance(token, str), (
        f"jwt.encode returned {type(token).__name__}, expected str. "
        "PyJWT 2.x is required; PyJWT 1.x is no longer supported."
    )

    # The str token round-trips through decode without .decode().
    decoded = jwt.decode(token, secret, algorithms=["HS256"])
    assert decoded["sub"] == "carol"
    assert decoded["groups"] == ["viewer"]