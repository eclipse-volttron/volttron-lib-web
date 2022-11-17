import gevent
import json
import jwt
import pytest

from deepdiff import DeepDiff
from urllib.parse import urlencode

from volttron.services.web.admin_endpoints import AdminEndpoints
from volttron.services.web.authenticate_endpoint import AuthenticateEndpoints
from volttron.utils.certs import CertWrapper
from volttron.utils.keystore import get_random_key

from volttrontesting.fixtures.cert_fixtures import certs_profile_1

from volttrontesting.platformwrapper import create_volttron_home, with_os_environ
from volttrontesting.web_utils import get_test_web_env


@pytest.mark.parametrize("encryption_type", ("private_key", "tls"))
def test_jwt_encode(encryption_type):
    volttron_home = create_volttron_home()
    with with_os_environ({'VOLTTRON_HOME': volttron_home}):
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
            new_claims = jwt.decode(token, decode_key, algorithms=algorithm)
        else:
            new_claims = jwt.decode(token, encoded_key, algorithms=algorithm)

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
            with certs_profile_1(volttron_home) as certs:
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

