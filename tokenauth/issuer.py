import base64
import collections
import contextlib
import dataclasses
import datetime
import http.client
import ipaddress
import json
import logging
import secrets
import typing

import paramiko.agent
import paramiko.message
import quart

from .common import AsyncJWTHelper, TokenPCKE, TokenVerifier


@dataclasses.dataclass(frozen=True)
class TokenIssuerItem:
    client_id: str
    state: str
    pcke_code_challenge: str
    nonce: str


# https://docs.python.org/3/library/collections.html#collections.OrderedDict
class TokenIssuerDict:

    cache: collections.OrderedDict

    def __init__(self, maxsize=1024):
        self.cache = collections.OrderedDict()
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        self.cache[key] = value
        self.cache.move_to_end(key)

    def __getitem__(self, key) -> TokenIssuerItem:
        if len(self.cache) > self.maxsize:
            self.cache.popitem(0)
        return self.cache[key]

    def __delitem__(self, key):
        del self.cache[key]

    def clear(self):
        self.cache.clear()

    def get(self, key, default=None) -> TokenIssuerItem | None:
        return self.cache.get(key, default)


class TokenIssuerKeyStore:

    keys: dict[str, paramiko.PKey]

    def __init__(self):
        self.keys = dict()

    def add(self, key: str, /):
        key_type, key_base64 = key.split(maxsplit=2)
        public_key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_base64))
        self.keys[public_key.fingerprint] = public_key

    def get(self, fingerprint: str, /) -> paramiko.PKey:
        return self.keys.get(fingerprint)

    def clear(self) -> None:
        return self.keys.clear()


class TokenIssuer:

    app: quart.Quart
    signer: AsyncJWTHelper
    keystore: TokenIssuerKeyStore
    cacher: TokenIssuerDict
    logger: logging.Logger
    nonce_route: str
    jwks_route: str
    verify_route: str

    def __init__(self,
                 app: quart.Quart,
                 signer: AsyncJWTHelper,
                 keystore: TokenIssuerKeyStore,
                 /,
                 nonce_route: str = '/nonce',
                 jwks_route: str = '/jwks',
                 verify_route: str = '/verify') -> None:

        self.app: typing.Final = app
        self.logger: typing.Final = app.logger
        self.keystore: typing.Final = keystore
        self.signer: typing.Final = signer
        self.cacher: typing.Final = TokenIssuerDict()

        self.nonce_route: typing.Final = nonce_route
        self.jwks_route: typing.Final = jwks_route
        self.verify_route: typing.Final = verify_route

        @self.app.before_serving
        async def _setup_routes() -> None:
            self.cacher.clear()
            app.add_url_rule(self.nonce_route, view_func=self.route_nonce_get, methods=["GET"])
            app.add_url_rule(self.nonce_route, view_func=self.route_nonce_post, methods=["POST"])
            app.add_url_rule(self.jwks_route, view_func=self.route_jwks_get, methods=["GET"])
            app.add_url_rule(self.verify_route, view_func=self.route_verify_get, methods=["GET"])
            pass

        @self.app.after_serving
        async def _teardown_routes() -> None:
            self.cacher.clear()

    async def generate_access_token(self, duration: datetime.timedelta, network: ipaddress.IPv4Network | ipaddress.IPv6Network, /) -> str:

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        access_claims_dict: typing.Final = {
            "iat": int(now.timestamp()),
            "exp": int((now + duration).timestamp()),
            "ipn": str(network),
            "ses": secrets.token_urlsafe(32),
        }
        # access_claims_dict.update({
        #     "iss": "issuer",
        #     "sub": "subject",
        # })
        access_claims_json = json.dumps(access_claims_dict).encode()
        return await self.signer.sign(access_claims_json)

    async def route_nonce_get(self) -> quart.ResponseReturnValue:

        query_required_keys = {'client_id', 'state', 'code_challenge'}
        for key in query_required_keys:
            if not quart.request.args.get(key):
                quart.abort(http.HTTPStatus.BAD_REQUEST)

        nonce_claim: typing.Final = {
            'client_id': quart.request.args.get('client_id'),
            "nonce": secrets.token_urlsafe(16),
            'state': quart.request.args.get('state'),
        }

        self.cacher[nonce_claim['state']] = TokenIssuerItem(
            client_id=nonce_claim['client_id'],
            state=nonce_claim['state'],
            pcke_code_challenge=quart.request.args.get('code_challenge', ''),
            nonce=nonce_claim['nonce'])

        return await self.signer.sign(nonce_claim)

    async def route_nonce_post(self) -> quart.ResponseReturnValue:

        # this is ugly, but it's written to fail as early
        # as possible at every step through the process.

        if not quart.request.is_json:
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        try:
            data = await quart.request.get_json()
        except json.JSONDecodeError:
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        if not isinstance(data, dict):
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        data_required_keys = {'client_id', 'state', 'code', 'code_verifier'}
        if set(data.keys()).intersection(data_required_keys) != data_required_keys:
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        state = pcke_code_verifier = nonce_signature = None
        if isinstance(data, dict):
            state = data.get('state')
            pcke_code_verifier = data.get('code_verifier')
            nonce_signature = data.get('code')
            if isinstance(nonce_signature, str):
                nonce_signature = base64.urlsafe_b64decode(nonce_signature.encode())

        if not all([state, pcke_code_verifier, nonce_signature]):
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        cache_item = self.cacher.get(state)
        if not cache_item:
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        # explicit delete so there can only be one attempt.
        del self.cacher[state]

        pcke = TokenPCKE(cache_item.pcke_code_challenge)
        if not pcke.verify(pcke_code_verifier):
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        remote_client_id = None
        with contextlib.suppress(Exception):
            remote_client_id = base64.urlsafe_b64decode(cache_item.client_id).decode()
        if not remote_client_id:
            quart.abort(http.HTTPStatus.BAD_REQUEST)

        remote_public_key = self.keystore.get(remote_client_id)
        if not remote_public_key:
            quart.abort(http.HTTPStatus.UNAUTHORIZED)

        signer_public_key = await self.signer.public_key()
        nonce: typing.Final = cache_item.nonce.encode() + signer_public_key.to_pem()

        signature_msg: typing.Final = paramiko.Message(nonce_signature)
        if not remote_public_key.verify_ssh_sig(nonce, signature_msg):
            quart.abort(http.HTTPStatus.UNAUTHORIZED)

        return await self.generate_access_token(datetime.timedelta(hours=12), ipaddress.ip_network(quart.request.remote_addr))

    async def route_jwks_get(self) -> quart.ResponseReturnValue:
        pubk = await self.signer.public_key()
        jwks = [pubk.to_dict() | {'use': 'sig'}]
        return jwks

    async def route_verify_get(self) -> quart.ResponseReturnValue:

        authorization_header = quart.request.headers.get('authorization')
        if not authorization_header:
            quart.abort(http.HTTPStatus.UNAUTHORIZED)

        access_token = authorization_header.split()[-1]
        if not access_token:
            quart.abort(http.HTTPStatus.UNAUTHORIZED)

        if not await TokenVerifier.verify_token(access_token, ipaddress.ip_address(quart.request.remote_addr), await self.signer.public_key()):
            quart.abort(http.HTTPStatus.UNAUTHORIZED)

        return ''
