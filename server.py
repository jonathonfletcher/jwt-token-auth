import asyncio
import base64
import http
import json
import logging
import os
import secrets
import datetime
import typing
import uuid
import ipaddress

import colorlog
import hypercorn.asyncio
import hypercorn.config
import hypercorn.middleware
import jose.jwt
import paramiko
import paramiko.util
import quart
import rich.pretty

from simpletoken import AsyncJWTHelper

BASEDIR: typing.Final = os.path.dirname(os.path.realpath(__file__))
TOKEN: typing.Final = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsD3+RokDgW4qjQ4wBIB7Ae4HaoYewkvyWaxz/u1hY9'
# key_type, key_base64 = TOKEN.split()
# public_key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_base64))
# pass

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
    "MAX_CONTENT_LENGTH": 512 * 1024,
    "BODY_TIMEOUT": 15,
    "RESPONSE_TIMEOUT": 15,
})

signer: typing.Final = AsyncJWTHelper(app.logger)


@app.before_serving
async def _before_serving() -> None:
    pass


@app.after_serving
async def _after_serving() -> None:
    pass


@app.route('/nonce', methods=['GET'])
async def _nonce_get() -> quart.ResponseReturnValue:
    await asyncio.to_thread(rich.pretty.pprint, quart.request.args, indent_guides=False)
    app.logger.info(quart.request.args)
    nonce_claim: typing.Final = {
        'client_id': quart.request.args.get('client_id'),
        "nonce": secrets.token_urlsafe(16),
        'state': quart.request.args.get('state'),
    }
    if nonce_claim['client_id'] and nonce_claim['state']:
        return await signer.sign(nonce_claim)
    return await quart.render_template('index.html')


@app.route('/nonce', methods=['POST'])
async def _nonce_post() -> quart.ResponseReturnValue:
    if not quart.request.is_json:
        return http.HTTPStatus.BAD_REQUEST

    try:
        data = await quart.request.get_json()
    except json.JSONDecodeError:
        return http.HTTPStatus.BAD_REQUEST

    nonce = nonce_signature = None
    if isinstance(data, dict):
        nonce = data.get('nonce')
        if isinstance(nonce, str):
            nonce = base64.urlsafe_b64decode(nonce.encode())
        nonce_signature = data.get('code')
        if isinstance(nonce_signature, str):
            nonce_signature = base64.urlsafe_b64decode(nonce_signature.encode())

    if not all([nonce, nonce_signature]):
        return http.HTTPStatus.BAD_REQUEST

    key_type, key_base64 = TOKEN.split()
    public_key = paramiko.PKey.from_type_string(key_type, base64.b64decode(key_base64))
    nonce_signature_msg = paramiko.Message(nonce_signature)
    if not public_key.verify_ssh_sig(nonce, nonce_signature_msg):
        return http.HTTPStatus.UNAUTHORIZED

    now = datetime.datetime.now(tz=datetime.UTC)
    claims_dict: typing.Final = {
        "exp": int(now.timestamp()),
        "iat": int((now + datetime.timedelta(hours=4)).timestamp()),
        "iss": "issuer",
        "sub": "subject",
        "ip.network": str(ipaddress.ip_network(quart.request.remote_addr)),
        "session.id": secrets.token_urlsafe(32),
    }
    claims_json = json.dumps(claims_dict).encode()
    return await signer.sign(claims_json)
    # return await quart.render_template('post.html')


@app.route('/jwks', methods=['GET'])
async def _jwks() -> quart.ResponseReturnValue:
    pubk = await signer.public_key()
    jwk = pubk.to_dict() | {'use': 'sig'}
    jwks = [jwk]
    print(f'{jwks=}')
    return jwks


@app.route('/', defaults={'site': None}, methods=['POST'])
@app.route('/<uuid:site>', methods=['POST'])
async def _root_route(site: uuid.UUID) -> quart.ResponseReturnValue:
    if not site:
        return await quart.render_template('index.html')

    try:
        app.logger.info(site)
        return await quart.render_template('index.html')
    except KeyError:
        return await quart.abort(http.HTTPStatus.BAD_GATEWAY)


if __name__ == "__main__":

    app_debug: typing.Final = app.config.get("DEBUG", False)
    app_port = app.config.get("PORT", 5055)
    app_host: typing.Final = app.config.get("HOST", "127.0.0.1")

    if app_debug:
        app.run(host=app_host, port=app_port, debug=app_debug)
    else:
        app_trusted_hosts: typing.Final = ["127.0.0.1", "::1"]
        app_bind_hosts: typing.Final = [x for x in app_trusted_hosts]

        # XXX: hack for development server.
        development_flag_file = os.path.join(BASEDIR, "development.txt")
        if os.path.exists(development_flag_file):
            app_port = 5055
            with open(development_flag_file) as ifp:
                app_bind_hosts.clear()
                app_bind_hosts.append("0.0.0.0")
                for line in [line.strip() for line in ifp.readlines()]:
                    app_trusted_hosts.append(line)

        config: typing.Final = hypercorn.config.Config()
        config.bind = [f"{host}:{app_port}" for host in app_bind_hosts]
        config.accesslog = "-"

        async def async_main():

            app.asgi_app = hypercorn.middleware.ProxyFixMiddleware(
                app.asgi_app
            )

            await hypercorn.asyncio.serve(app, config)

        asyncio.run(async_main())
