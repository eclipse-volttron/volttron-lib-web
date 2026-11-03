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

from functools import lru_cache
from http.cookies import SimpleCookie
import logging

from volttron.utils.context import ClientContext

try:
    import jwt
except ImportError:
    pass

# Used outside so we make it available through this file.
# removing below import from init as this cause jinja2 to be imported and causes gevent error when running
# vctl web command even though the vct web command itself complete successfully
# from . platform_web_service import PlatformWebService

_log = logging.getLogger(__name__)


class NotAuthorized(Exception):
    pass


def get_bearer(env):

    # Test if HTTP_AUTHORIZATION header is passed
    http_auth = env.get('HTTP_AUTHORIZATION')
    if http_auth:
        auth_type, bearer = http_auth.split(' ')
        if auth_type.upper() != 'BEARER':
            raise NotAuthorized("Invalid HTTP_AUTHORIZATION header passed, must be Bearer")
        else:
            return bearer
    else:
        cookiestr = env.get('HTTP_COOKIE')
        if not cookiestr:
            raise NotAuthorized()
        cookie = SimpleCookie(cookiestr)
        if 'Bearer' in cookie:
            bearer = cookie.get('Bearer').value
            return bearer
        else:
            return None


def get_authorization_bearer(env):
    """Return the token from an ``Authorization: Bearer`` header, or None.

    Unlike get_bearer this never reads the cookie, which a browser attaches to requests that another site makes.
    """
    parts = (env.get('HTTP_AUTHORIZATION') or '').split(' ')
    if len(parts) != 2 or parts[0].upper() != 'BEARER' or not parts[1]:
        return None
    return parts[1]


# PyJWT pairs each ECDSA algorithm with exactly one curve.
_EC_CURVE_ALGORITHMS = {'secp256r1': 'ES256', 'secp384r1': 'ES384', 'secp521r1': 'ES512'}


def jwt_algorithm_for_key(key):
    """
    The JWS algorithm that signs or verifies with ``key``: ``RS256`` for an RSA key, ``ES256``/``ES384``/``ES512``
    for an EC key on P-256/P-384/P-521 and ``EdDSA`` for an Ed25519 or Ed448 key.

    ``key`` is a PEM private or public key as bytes or str (what ``CertWrapper`` returns for the web TLS files) or a
    ``cryptography`` key object. Any other key raises ``ValueError`` naming the type, so a ``web-ssl-key`` the
    service cannot sign tokens with is refused at start-up instead of at the first login.
    """
    if isinstance(key, (bytes, str)):
        return _jwt_algorithm_for_pem(key if isinstance(key, bytes) else key.encode('utf-8'))
    return _jwt_algorithm_for_key_object(key)


@lru_cache(maxsize=16)
def _jwt_algorithm_for_pem(pem: bytes):
    # The same PEM is checked on every token issue and verification; parsing it once is enough.
    from cryptography.hazmat.primitives import serialization
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except ValueError:
        try:
            key = serialization.load_pem_public_key(pem)
        except ValueError as e:
            raise ValueError(f"Not a PEM private or public key: {e}") from None
    return _jwt_algorithm_for_key_object(key)


def _jwt_algorithm_for_key_object(key):
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return 'RS256'
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        algorithm = _EC_CURVE_ALGORITHMS.get(key.curve.name)
        if algorithm is None:
            raise ValueError(f"EC key on curve {key.curve.name} cannot sign JWTs; use P-256, P-384 or P-521")
        return algorithm
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey,
                        ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return 'EdDSA'
    raise ValueError(f"{type(key).__name__} cannot sign JWTs; use an RSA, EC (P-256/P-384/P-521) or Ed25519 key")


def get_user_claim_from_bearer(bearer, web_secret_key=None, tls_public_key=None):
    if web_secret_key is None and tls_public_key is None:
        raise ValueError("web_secret_key or tls_public_key must be set")
    if web_secret_key is not None and tls_public_key is not None:
        raise ValueError("web_secret_key or tls_public_key must be set not both")

    if web_secret_key is not None:
        algorithm = 'HS256'
        pubkey = web_secret_key
    else:
        # The algorithm follows the key type so that the same key the server uses for TLS can sign tokens whether
        # it is RSA or EC; the list still holds exactly one entry, so a token naming any other algorithm is rejected.
        algorithm = jwt_algorithm_for_key(tls_public_key)
        pubkey = tls_public_key

    claims = jwt.decode(bearer, pubkey, algorithms=[algorithm])
    return claims
