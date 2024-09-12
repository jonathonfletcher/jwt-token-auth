import base64
import contextlib
import datetime as dt
import hashlib
import http
import http.client
import inspect
import json
import logging
import os
import secrets
import typing
import urllib.error
import urllib.parse
import urllib.request
import jose.backends
import rich.pretty
import colorlog
import jose.jwk
import jose.jwt
import paramiko
import paramiko.agent
import paramiko.message

from simpletoken import JWTHelper


class Access:

    timeout_expiry: dt.datetime
    token_duration: typing.Final = 300
    timeout: float
    logger: logging.Logger

    def __init__(self, /, timeout: float = 5, logger: typing.Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.timeout_expiry = dt.datetime.now(tz=dt.timezone.utc) - dt.timedelta(seconds=1)
        self.timeout = timeout

    def _request(self, url: str | urllib.parse.ParseResult, method: str, headers: dict[str, str | int], data: typing.Optional[str | dict] = None) -> str | dict | None:
        if isinstance(url, urllib.parse.ParseResult):
            url = url.geturl()

        now = dt.datetime.now(tz=dt.timezone.utc)
        if now > self.timeout_expiry:
            try:
                req: typing.Final = urllib.request.Request(url, headers=headers, method=method, data=data)
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    if isinstance(res, http.client.HTTPResponse):
                        if res.status in [http.HTTPStatus.OK]:
                            content = bytes(res.read()).decode()
                            content_type = res.getheader('Content-Type')
                            if any([content_type.find('application/json') >= 0, content_type.find('text/plain') >= 0]):
                                with contextlib.suppress(json.decoder.JSONDecodeError):
                                    content = json.loads(content)
                            return content
            except urllib.error.HTTPError as ex:
                if ex.code not in [http.HTTPStatus.NOT_FOUND]:
                    self.logger.error(f"{self.__class__.__name__}.{inspect.currentframe().f_code.co_name}: {ex=}")
            except urllib.error.URLError:
                self.timeout_expiry = now + dt.timedelta(seconds=1)
            # except Exception as ex:
            #     self.logger.error(f"{self.__class__.__name__}.{inspect.currentframe().f_code.co_name}: {ex=}")
        return None

    def get(self, url: str) -> str | dict | None:
        return self._request(url, 'GET', {})

    def post(self, url: str, data: dict) -> str | dict | None:
        return self._request(url, 'POST', {'Content-Type': 'application/json'}, data=json.dumps(data).encode())


class PCKE:

    challenge: str
    verifier: str
    method: str = 'S256'

    def __init__(self):
        sha256: typing.Final = hashlib.sha256()
        self.verifier: typing.Final = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().replace("=", "")
        sha256.update(self.verifier.encode())
        self.challenge: typing.Final = base64.urlsafe_b64encode(sha256.digest()).decode().replace("=", "")


class AccessHelper:

    fingerprint: str
    private_key: paramiko.PKey
    client_id: str
    transport: Access

    _access_token: str

    def __init__(self, fingerprint, /, logger: typing.Optional[logging.Logger] = None):
        self.fingerprint = fingerprint

        self.transport = Access()

        agent = paramiko.agent.Agent()
        self.private_key = None
        for agent_key in agent.get_keys():
            if agent_key.fingerprint == self.fingerprint:
                self.private_key = agent_key
                break
        
        if self.private_key:
            self.client_id = base64.urlsafe_b64encode(self.private_key.fingerprint.encode()).decode()

    def _get_jwks(self, endpoint: urllib.parse.ParseResult) -> list[JWTHelper]:
        jwks = self.transport.get(endpoint._replace(path='/jwks'))
        if isinstance(jwks, list):
            jwks = list(map(lambda x: JWTHelper(logger, key=jose.jwk.construct(x)), jwks))
        elif isinstance(jwks, dict):
            jwks = [JWTHelper(logger, key=jose.jwk.construct(jwks))]
        elif jwks is None:
            jwks = []
        return jwks

    def _get_access_token(self):
        pcke = PCKE()
        state = secrets.token_urlsafe(32)

        token_endpoint: typing.Final = urllib.parse.urlparse('https://dev.castabouts.net/nonce')
        request_params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'state': state,
            'code_challenge': pcke.challenge,
            'code_challenge_method': pcke.method
        }

        nonce_token = self.transport.get(token_endpoint._replace(query=urllib.parse.urlencode(request_params)))

        for jwk in self._get_jwks(token_endpoint._replace(path='/jwks')):
            print(f'{jwk=}')
            try:
                decoded_nonce_token = jwk.verify(nonce_token)
            except Exception as ex:
                decoded_nonce_token = None

        if isinstance(decoded_nonce_token, bytes) or isinstance(decoded_nonce_token, str):
            decoded_nonce_token = json.loads(decoded_nonce_token)

        assert state == decoded_nonce_token.get('state')

        nonce = decoded_nonce_token.get('nonce')
        if isinstance(nonce, str):
            nonce = nonce.encode()

        ssh_msg = paramiko.message.Message(self.private_key.sign_ssh_data(nonce))
        rich.pretty.pprint(ssh_msg)
        nonce_signature = ssh_msg.asbytes()

        post_body: typing.Final = {
            "grant_type": "authorization_code",
            'client_id': self.client_id,
            "nonce": base64.urlsafe_b64encode(nonce).decode(),
            "code": base64.urlsafe_b64encode(nonce_signature).decode(),
            'code_verifier': pcke.verifier
        }

        rich.pretty.pprint(post_body)
        rich.pretty.pprint(f'{nonce=}')
        rich.pretty.pprint(f'{nonce_signature=}')

        return self.transport.post(token_endpoint, post_body)
        pass


    # @property
    # def access_token(self) -> str:
    #     if self._access_token in [None, '']:
    #         sel


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
    logger.addHandler(handler)

    o = AccessHelper('SHA256:cQKF3Vquko1VMT8b+DHtilunzY5EW3bcUctBcSNBhw4')
    access_token = o._get_access_token()
    # pcke = PCKE()
    # agent = paramiko.agent.Agent()
    # private_key = list(agent.get_keys()).pop()
    # print(f'{private_key.fingerprint=}')

    # state = secrets.token_urlsafe(32)
    # client_id = base64.urlsafe_b64encode(private_key.fingerprint.encode()).decode()

    # token_endpoint: typing.Final = urllib.parse.urlparse('https://dev.castabouts.net/nonce')
    # request_params = {
    #     'response_type': 'code',
    #     'client_id': client_id,
    #     'state': state,
    #     'code_challenge': pcke.challenge,
    #     'code_challenge_method': pcke.method
    # }

    # obj = Access()

    # nonce_token = obj.get(token_endpoint._replace(query=urllib.parse.urlencode(request_params)))
    # print(f'{nonce_token=}')
    # pass

    # jwks = obj.get(token_endpoint._replace(path='/jwks'))
    # if isinstance(jwks, list):
    #     jwks = list(map(lambda x: JWTHelper(logger, key=jose.jwk.construct(x)), jwks))
    # print(f'{jwks=}')
    # pass

    # for jwk in jwks:
    #     try:
    #         decoded_token = jwk.verify(nonce_token)
    #     except Exception as ex:
    #         print(f'{ex=}')
    #         decoded_token = None
        
    # pass
    # # {'alg': 'ES256', 'crv': 'P-256', 'kid': '8878a23f-2489-4045-989e-4d2f3ec1ae1a', 'kty': 'EC', 'use': 'sig', 'x': 'PatzB2HJzZOzmqQyYpQYqn3SAXoVYWrZKmMgJnfK94I', 'y': 'qDb1kUd13fRTN2UNmcgSoQoyqeF_C1MsFlY_a87csnY'}]
    # if isinstance(decoded_token, bytes) or isinstance(decoded_token, str):
    #     decoded_token = json.loads(decoded_token)

    # assert state == decoded_token.get('state')

    # nonce = decoded_token.get('nonce')
    # if isinstance(nonce, str):
    #     nonce = nonce.encode()

    # ssh_msg = paramiko.message.Message(private_key.sign_ssh_data(nonce))
    # rich.pretty.pprint(ssh_msg)
    # nonce_signature = ssh_msg.asbytes()

    # post_body: typing.Final = {
    #     "grant_type": "authorization_code",
    #     'client_id': client_id,
    #     "nonce": base64.urlsafe_b64encode(nonce).decode(),
    #     "code": base64.urlsafe_b64encode(nonce_signature).decode(),
    #     'code_verifier': pcke.verifier
    # }

    # rich.pretty.pprint(post_body)
    # rich.pretty.pprint(f'{nonce=}')
    # rich.pretty.pprint(f'{nonce_signature=}')

    # r = obj.post(token_endpoint, post_body)
    pass
