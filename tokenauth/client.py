import base64
import contextlib
import dataclasses
import datetime
import http.client
import inspect
import ipaddress
import json
import logging
import secrets
import typing
import urllib.error
import urllib.parse
import urllib.request

import jose.backends
import jose.backends.cryptography_backend
import jose.constants
import jose.jwe
import jose.jwk
import jose.jws
import jose.utils
import paramiko.agent
import paramiko.message

from .common import JWTHelper, TokenPCKE

# ACCESS_ENDPOINT: typing.Final = urllib.parse.urlparse('https://dev.castabouts.net/nonce')
ACCESS_ENDPOINT: typing.Final = urllib.parse.urlparse('http://127.0.0.1:5055/nonce')
JWKS_ENDPOINT: typing.Final = ACCESS_ENDPOINT._replace(path='/jwks')
VERIFY_ENDPOINT: typing.Final = ACCESS_ENDPOINT._replace(path='/verify')


class Token:

    access_token_str: str
    decoded_token: dict

    def __init__(self, access_token_str: str, jwk: jose.backends.base.Key, /):
        self.access_token_str = access_token_str
        self.jwk = jwk
        self.decoded_token = self.jwk.verify(self.access_token_str)
        if isinstance(self.decoded_token, bytes) or isinstance(self.decoded_token, str):
            self.decoded_token = json.loads(self.decoded_token)

    @property
    def iat(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.decoded_token.get('iat', 0), datetime.timezone.utc)

    @property
    def exp(self) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(self.decoded_token.get('exp', 0), datetime.timezone.utc)

    @property
    def ipn(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.decoded_token.get('ipn', '127.0.0.1/31'))

    @property
    def valid(self) -> bool:
        if not all([self.access_token_str, self.decoded_token]):
            return False

        now = datetime.datetime.now(tz=datetime.timezone.utc).replace(microsecond=0)
        return all([self.iat <= now, self.exp > now])

    def __str__(self):
        return self.access_token_str

    def __repr__(self):
        return self.__str__()
        return self.access_token_str


@dataclasses.dataclass(frozen=True)
class TokenHTTPResult:
    status: http.HTTPStatus
    data: bytes | None


class TokenHTTPHelper:

    timeout_expiry: datetime.datetime
    token_duration: typing.Final = 300
    timeout: float
    logger: logging.Logger

    def __init__(self, /, timeout: float = 120, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.timeout_expiry = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(seconds=1)
        self.timeout = timeout

    def _request(self, url: str | urllib.parse.ParseResult, method: str, headers: dict[str, str], data: bytes | dict | None = None) -> TokenHTTPResult:
        if isinstance(url, urllib.parse.ParseResult):
            url = url.geturl()

        result_status = http.HTTPStatus.BAD_GATEWAY
        result_data = None

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if now > self.timeout_expiry:
            try:
                req: typing.Final = urllib.request.Request(url, headers=headers, method=method, data=data)
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    if isinstance(res, http.client.HTTPResponse):
                        if res.status in [http.HTTPStatus.OK, http.HTTPStatus.NO_CONTENT]:
                            content = b''
                            if res.status in [http.HTTPStatus.OK]:
                                content = bytes(res.read()).decode()
                                content_type = res.getheader('Content-Type', '')
                                if any([content_type.find('application/json') >= 0, content_type.find('text/plain') >= 0]):
                                    with contextlib.suppress(json.decoder.JSONDecodeError):
                                        content = json.loads(content)
                            result_status = res.status
                            result_data = content
            except urllib.error.HTTPError as ex:
                result_status = ex.code
                if ex.code not in [http.HTTPStatus.NOT_FOUND]:
                    self.logger.error(f"{self.__class__.__name__}.{inspect.currentframe().f_code.co_name}: {ex=}")
            except urllib.error.URLError:
                result_status = http.HTTPStatus.REQUEST_TIMEOUT
                self.timeout_expiry = now + datetime.timedelta(seconds=1)
            # except Exception as ex:
            #     self.logger.error(f"{self.__class__.__name__}.{inspect.currentframe().f_code.co_name}: {ex=}")

        return TokenHTTPResult(result_status, result_data)

    def get(self, url: str | urllib.parse.ParseResult, /, headers: dict[str, str] | None = None) -> TokenHTTPResult:
        headers = headers or {}
        return self._request(url, 'GET', headers=headers)

    def post(self, url: str | urllib.parse.ParseResult, data: dict, /) -> TokenHTTPResult:
        return self._request(url, 'POST', {'Content-Type': 'application/json'}, data=json.dumps(data).encode())


class TokenClient:

    logger: logging.Logger
    client_id: str
    transport: TokenHTTPHelper
    private_key: paramiko.PKey
    jwks: list[JWTHelper]
    token_endpoint: urllib.parse.ParseResult

    _access_token: Token | None

    def __init__(self, /, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger(__name__)

        self.transport = TokenHTTPHelper()

        self.token_endpoint = ACCESS_ENDPOINT
        self.jwks = self._get_jwks(JWKS_ENDPOINT)

        self.client_id = None

        self._access_token = None

    def use(self, fingerprint: str, /) -> bool:

        self.private_key = None
        self.client_id = None

        agent = paramiko.agent.Agent()
        if not agent:
            return False

        for agent_key in agent.get_keys():
            if agent_key.fingerprint == fingerprint:
                self.private_key = agent_key
                break

        if not self.private_key:
            return False

        self.client_id = base64.urlsafe_b64encode(self.private_key.fingerprint.encode()).decode()

        return True

    def _get_jwks(self, endpoint: urllib.parse.ParseResult, /) -> list[JWTHelper]:
        jwks = None
        response = self.transport.get(endpoint)
        if response.status in [http.HTTPStatus.OK]:
            jwks = response.data
            if isinstance(jwks, list):
                jwks = list(map(lambda x: JWTHelper(self.logger, key=jose.jwk.construct(x)), jwks))
            elif isinstance(jwks, dict):
                jwks = [JWTHelper(self.logger, key=jose.jwk.construct(jwks))]
            elif jwks is None:
                jwks = []
        return jwks

    def _get_decoded_token(self, access_token: str, /) -> Token | None:
        for jwk in self.jwks:
            try:
                decoded_token = jwk.verify(access_token)
                break
            except jose.JWSError:
                decoded_token = None

        if not all([decoded_token, jwk]):
            return None

        return Token(access_token, jwk)

    def _get_access_token(self, /):
        if not self.private_key:
            return None

        pcke: typing.Final = TokenPCKE()
        client_state: typing.Final = secrets.token_urlsafe(32)

        nonce_request_query = {
            'response_type': 'code',
            'client_id': self.client_id,
            'state': client_state,
            'code_challenge': pcke.challenge,
            'code_challenge_method': pcke.method
        }
        nonce_response = self.transport.get(self.token_endpoint._replace(query=urllib.parse.urlencode(nonce_request_query)))

        nonce_token = None
        if nonce_response.status in [http.HTTPStatus.OK]:
            nonce_token = nonce_response.data

        for jwk in self.jwks:
            try:
                decoded_nonce_token = jwk.verify(nonce_token)
                break
            except jose.JWSError:
                decoded_nonce_token = None

        if isinstance(decoded_nonce_token, bytes) or isinstance(decoded_nonce_token, str):
            decoded_nonce_token = json.loads(decoded_nonce_token)

        if not all([jwk, decoded_nonce_token]):
            return None

        assert client_state == decoded_nonce_token.get('state')

        nonce = decoded_nonce_token.get('nonce')
        if isinstance(nonce, str):
            nonce = nonce.encode()

        # Add the pem of the public key from the server to the nonce,
        # so the server can verify the signature against the nonce
        # it send with the server's public key appended (avoid potential mitm)
        nonce = nonce + jwk.public_key().to_pem()

        nonce_ssh_msg = paramiko.message.Message(self.private_key.sign_ssh_data(nonce))
        signature = nonce_ssh_msg.asbytes()

        nonce_post_body: typing.Final = {
            "grant_type": "authorization_code",
            'client_id': self.client_id,
            'state': client_state,
            "code": base64.urlsafe_b64encode(signature).decode(),
            'code_verifier': pcke.verifier
        }

        post_response = self.transport.post(self.token_endpoint, nonce_post_body)
        if post_response.status in [http.HTTPStatus.OK]:
            return post_response.data
        return None

    def verify(self, token: Token | str) -> bool:
        if token:
            post_response = self.transport.get(JWKS_ENDPOINT._replace(path='/verify'), headers={'Authorization': f"Bearer {token!s}"})
            return post_response.status in [http.HTTPStatus.OK, http.HTTPStatus.NO_CONTENT]
        return False

    @property
    def fingerprint(self) -> str | None:
        if self.private_key:
            return self.private_key.fingerprint
        return None

    @property
    def access_token(self) -> Token | None:
        if self._access_token:
            if not self._access_token.valid:
                self._access_token = None
        if self._access_token is None:
            access_token_str = self._get_access_token()
            if access_token_str:
                self._access_token = self._get_decoded_token(access_token_str)
        return self._access_token
