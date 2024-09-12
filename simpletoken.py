import asyncio
import logging
import typing

import colorlog
import cryptography.hazmat.primitives.asymmetric.ec as ecdsa
import jose.backends
import jose.backends.cryptography_backend
import jose.constants
import jose.jwk
import jose.jws
import jose.utils


class JWTHelper:

    logger: logging.Logger
    _private_key: jose.backends.base.Key = None
    _public_key: jose.backends.base.Key = None

    def _generate_key(self) -> jose.backends.base.Key:
        tkey = ecdsa.generate_private_key(ecdsa.SECP256R1())
        return jose.backends.cryptography_backend.CryptographyECKey(tkey, jose.constants.ALGORITHMS.ES256)


    def __init__(self, logger: logging.Logger, /, key: typing.Optional[jose.backends.base.Key] = None) -> None:
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

    def sign(self, claims: bytes | typing.Mapping[str, typing.Any]) -> str:
        if not self._private_key:
            raise jose.JWSError('no private key]')
        else:
            private_key: typing.Final = self._private_key.to_dict()
            return jose.jws.sign(claims, private_key, algorithm=private_key['alg'])

    def verify(self, token: str) -> bytes | typing.Mapping[str, typing.Any]:
        public_key: typing.Final = self._public_key.to_dict()
        return jose.jws.verify(token, public_key, public_key['alg'])


class AsyncJWTHelper:

    helper: JWTHelper

    def __init__(self, logger: logging.Logger, /, key: typing.Optional[jose.backends.base.Key] = None) -> None:
        self.helper = JWTHelper(logger, key=key)

    async def public_key(self) -> jose.backends.base.Key:
        return self.helper.public_key()

    async def sign(self, claims: bytes | typing.Mapping[str, typing.Any]) -> str:
        return await asyncio.to_thread(self.helper.sign, claims)

    async def verify(self, token: str) -> bytes | typing.Mapping[str, typing.Any]:
        return await asyncio.to_thread(self.helper.verify, token)


if __name__ == '__main__':

    def sync_main(logger: logging.Logger, key: jose.backends.base.Key, /):
        helper = JWTHelper(logger, key=key)

        pubk = helper.public_key()
        print(f"{pubk.to_dict()=}")

        claims_in = 'hello world'.encode()
        claims_token = helper.sign(claims_in)

        print(f'{claims_token=}')

        claims_out = helper.verify(claims_token)

        assert claims_in == claims_out

    async def async_main(logger: logging.Logger, key: jose.backends.base.Key, /):
        helper = AsyncJWTHelper(logger, key=key)

        pubk = await helper.public_key()
        print(f"{pubk.to_dict()=}")

        claims_in = 'hello world'.encode()
        claims_token = await helper.sign(claims_in)

        print(f'{claims_token=}')

        claims_out = await helper.verify(claims_token)

        assert claims_in == claims_out

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
    logger.addHandler(handler)

    tkey = ecdsa.generate_private_key(ecdsa.SECP256R1())
    key = jose.backends.cryptography_backend.CryptographyECKey(tkey, jose.constants.ALGORITHMS.ES256)

    # sync_main(logger, key)

    asyncio.run(async_main(logger, key))
    # message_jwt = claims_token.encode("utf-8")
    # signing_input, crypto_segment = message_jwt.rsplit(b".", 1)
    # header_segment, claims_segment = signing_input.split(b".", 1)
    # header_data = jose.utils.base64url_decode(header_segment)
    pass
