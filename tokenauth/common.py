import asyncio
import base64
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import typing

import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec
import ecdsa
import jose.backends
import jose.backends.cryptography_backend
import jose.constants
import jose.jwe
import jose.jwk
import jose.jws
import jose.utils


class JWTHelper:

    logger: logging.Logger
    _private_key: jose.backends.base.Key | None = None
    _public_key: jose.backends.base.Key | None = None

    def _generate_key(self) -> jose.backends.base.Key:
        tkey = cryptography_ec.generate_private_key(cryptography_ec.SECP256R1())
        return jose.backends.cryptography_backend.CryptographyECKey(tkey, jose.constants.ALGORITHMS.ES256)

    def __init__(self, logger: logging.Logger, /, key: jose.backends.base.Key | None = None) -> None:
        self.logger: typing.Final = logger
        key = key or self._generate_key()
        if not key.is_public():
            self._private_key = key
            assert any([self._private_key is None, not self._private_key.is_public()])
        self._public_key = key.public_key()
        assert self._public_key.is_public()
        pass

    def public_key(self) -> jose.backends.base.Key:
        return self._public_key

    def sign(self, claims: bytes | typing.Mapping[str, typing.Any], /) -> str:
        if not self._private_key:
            raise jose.JWSError('no private key]')
        else:
            private_key: typing.Final = self._private_key.to_dict()
            return jose.jws.sign(claims, private_key, algorithm=private_key['alg'])

    def verify(self, token: str, /) -> bytes | typing.Mapping[str, typing.Any]:
        public_key: typing.Final = self._public_key.to_dict()
        return jose.jws.verify(token, public_key, public_key['alg'], verify=True)


class AsyncJWTHelper:

    helper: JWTHelper

    def __init__(self, logger: logging.Logger, /, key: jose.backends.base.Key | None = None) -> None:
        self.helper = JWTHelper(logger, key=key)

    async def public_key(self) -> jose.backends.base.Key:
        return self.helper.public_key()

    async def sign(self, claims: bytes | typing.Mapping[str, typing.Any], /) -> str:
        return await asyncio.to_thread(self.helper.sign, claims)

    async def verify(self, token: str, /) -> bytes | typing.Mapping[str, typing.Any]:
        return await asyncio.to_thread(self.helper.verify, token)


class TokenPCKE:

    challenge: str | None
    verifier: str
    method: str = 'S256'

    def __init__(self, challenge: str | None = None):
        self.challenge = challenge
        if challenge is None:
            sha256: typing.Final = hashlib.sha256()
            self.verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().replace("=", "")
            sha256.update(self.verifier.encode())
            self.challenge = base64.urlsafe_b64encode(sha256.digest()).decode().replace("=", "")

    def verify(self, verifier: str, /):
        sha256: typing.Final = hashlib.sha256()
        sha256.update(verifier.encode())
        challenge = base64.urlsafe_b64encode(sha256.digest()).decode().replace("=", "")
        return self.challenge == challenge


class TokenUtils:

    @staticmethod
    def read_signing_key(filename: os.PathLike) -> jose.backends.base.Key:
        if os.path.exists(filename):
            with open(filename) as ifp:
                tkey = ecdsa.SigningKey.from_pem(ifp.read())
                return jose.backends.cryptography_backend.CryptographyECKey(tkey, jose.constants.ALGORITHMS.ES256)
        return None


class TokenVerifier:

    @staticmethod
    async def verify_token(access_token: str, client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, public_key: jose.backends.base.Key | dict, /) -> bool:

        if isinstance(public_key, jose.backends.base.Key):
            public_key = public_key.to_dict()

        decoded_access_token = jose.jws.verify(access_token, public_key, public_key['alg'])
        if not decoded_access_token:
            return False

        try:
            decoded_access_token = json.loads(decoded_access_token)
        except Exception:
            return False

        if not isinstance(decoded_access_token, dict):
            return False

        now = datetime.datetime.now(tz=datetime.timezone.utc).replace(microsecond=0).timestamp()
        token_iat = decoded_access_token.get('iat', 0)
        if token_iat > now:
            return False

        token_exp = decoded_access_token.get('exp', 0)
        if token_exp <= now:
            return False

        try:
            token_ip_network = ipaddress.ip_network(decoded_access_token.get('ipn', ''))
        except ValueError:
            return False

        if client_ip not in token_ip_network:
            return False

        return True
