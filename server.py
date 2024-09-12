import asyncio
import base64
import contextlib
import datetime
import http
import ipaddress
import json
import logging
import os
import secrets
import typing
import uuid

import colorlog
import hypercorn.asyncio
import hypercorn.config
import hypercorn.middleware
import paramiko
import paramiko.util
import quart

from support import (ACCESS_ENDPOINT, JWKS_ENDPOINT, AsyncJWTHelper, TokenServerDict,
                     TokenServerItem, TokenServerKeyStore, TokenPCKE)

BASEDIR: typing.Final = os.path.dirname(os.path.realpath(__file__))
TOKEN: typing.Final = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsD3+RokDgW4qjQ4wBIB7Ae4HaoYewkvyWaxz/u1hY9'

app: typing.Final = quart.Quart(__name__)

app.logger.setLevel(logging.INFO)
for handler in app.logger.handlers:
    if isinstance(handler, logging.StreamHandler):
        app.logger.removeHandler(handler)
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
app.logger.addHandler(handler)

app.config.from_mapping({
    "DEBUG": False,
    "PORT": 5555,
    "SECRET_KEY": uuid.uuid4().hex,
    "SESSION_COOKIE_HTTPONLY": True,
    "TEMPLATES_AUTO_RELOAD": True,
    "SEND_FILE_MAX_AGE_DEFAULT": 30,
    "MAX_CONTENT_LENGTH": 8 * 1024,
    "BODY_TIMEOUT": 15,
    "RESPONSE_TIMEOUT": 15,
})

signer: typing.Final = AsyncJWTHelper(app.logger)
cacher: typing.Final = TokenServerDict()
keystore: typing.Final = TokenServerKeyStore()


@app.before_serving
async def _before_serving() -> None:
    keystore.add(TOKEN)
    pass


@app.after_serving
async def _after_serving() -> None:
    keystore.clear()
    pass


@app.route(ACCESS_ENDPOINT.path, methods=['GET'])
async def _nonce_get() -> quart.ResponseReturnValue:

    query_required_keys = {'client_id', 'state', 'code_challenge'}
    for key in query_required_keys:
        if not quart.request.args.get(key):
            quart.abort(http.HTTPStatus.BAD_REQUEST)

    nonce_claim: typing.Final = {
        'client_id': quart.request.args.get('client_id'),
        "nonce": secrets.token_urlsafe(16),
        'state': quart.request.args.get('state'),
    }

    cacher[nonce_claim['state']] = TokenServerItem(
        client_id=nonce_claim['client_id'],
        state=nonce_claim['state'],
        pcke_code_challenge=quart.request.args.get('code_challenge', ''),
        nonce=nonce_claim['nonce'])

    return await signer.sign(nonce_claim)


@app.route(ACCESS_ENDPOINT.path, methods=['POST'])
async def _nonce_post() -> quart.ResponseReturnValue:

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

    cache_item: TokenServerItem = cacher.get(state)
    if not cache_item:
        quart.abort(http.HTTPStatus.BAD_REQUEST)

    # explicit delete so there can only be one attempt.
    del cacher[state]

    pcke = TokenPCKE(cache_item.pcke_code_challenge)
    if not pcke.verify(pcke_code_verifier):
        quart.abort(http.HTTPStatus.BAD_REQUEST)

    key_hash = None
    with contextlib.suppress(Exception):
        key_hash = base64.urlsafe_b64decode(cache_item.client_id).decode()
    public_key = keystore.get(key_hash)
    if not public_key:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    nonce = cache_item.nonce
    if isinstance(nonce, str):
        nonce = nonce.encode()

    signer_public_key = await signer.public_key()
    nonce = nonce + signer_public_key.to_pem()

    # remote_key_type, remote_key_base64 = TOKEN.split()
    # remote_public_key = paramiko.PKey.from_type_string(remote_key_type, base64.b64decode(remote_key_base64))
    # if not remote_key_hash == remote_public_key.fingerprint:
    #     quart.abort(http.HTTPStatus.UNAUTHORIZED)

    signature_msg = paramiko.Message(nonce_signature)
    if not public_key.verify_ssh_sig(nonce, signature_msg):
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    now = datetime.datetime.now(tz=datetime.UTC)
    access_claims_dict: typing.Final = {
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(hours=4)).timestamp()),
        "iss": "issuer",
        "sub": "subject",
        "ipn": str(ipaddress.ip_network(quart.request.remote_addr)),
        "session.id": secrets.token_urlsafe(32),
    }
    access_claims_json = json.dumps(access_claims_dict).encode()
    return await signer.sign(access_claims_json)


@app.route(JWKS_ENDPOINT.path, methods=['GET'])
async def _jwks_get() -> quart.ResponseReturnValue:
    pubk = await signer.public_key()
    jwk = pubk.to_dict() | {'use': 'sig'}
    jwks = [jwk]
    return jwks


@app.route('/verify')
async def _verify_get() -> quart.ResponseReturnValue:

    authorization_header = quart.request.headers.get('authorization')
    if not authorization_header:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    access_token = authorization_header.split()[-1]
    if not access_token:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    decoded_access_token = await signer.verify(access_token)
    if not decoded_access_token:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    try:
        decoded_access_token = await asyncio.to_thread(json.loads, decoded_access_token)
    except Exception:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    if not isinstance(decoded_access_token, dict):
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    now = int(datetime.datetime.now(tz=datetime.UTC).timestamp())
    token_iat = decoded_access_token.get('iat', 0)
    if token_iat >= now:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    token_exp = decoded_access_token.get('exp', 0)
    if token_exp < now:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    try:
        token_ip_network = ipaddress.ip_network(decoded_access_token.get('ipn', ''))
        client_ip = ipaddress.ip_address(quart.request.remote_addr)
    except ValueError:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    if client_ip not in token_ip_network:
        quart.abort(http.HTTPStatus.UNAUTHORIZED)

    return ''


if __name__ == "__main__":

    app_debug: typing.Final = app.config.get("DEBUG", False)
    app_port = app.config.get("PORT", 5055)
    app_host: typing.Final = app.config.get("HOST", "127.0.0.1")

    if app_debug:
        app.run(host=app_host, port=app_port, debug=app_debug)
    else:
        app_bind_hosts: typing.Final = ["127.0.0.1", "::1"]

        # XXX: hack for development server.
        development_flag_file = os.path.join(BASEDIR, "development.txt")
        if os.path.exists(development_flag_file):
            app_port = 5055
            app_bind_hosts.clear()
            app_bind_hosts.append("0.0.0.0")

        config: typing.Final = hypercorn.config.Config()
        config.bind = [f"{host}:{app_port}" for host in app_bind_hosts]
        config.accesslog = "-"

        async def async_main():

            app.asgi_app = hypercorn.middleware.ProxyFixMiddleware(
                app.asgi_app
            )

            await hypercorn.asyncio.serve(app, config)

        asyncio.run(async_main())
