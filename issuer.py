import asyncio
import datetime
import ipaddress
import logging
import os
import pathlib
import typing
import uuid

import colorlog
import hypercorn.asyncio
import hypercorn.config
import hypercorn.middleware
import quart

from tokenauth import (AsyncJWTHelper, TokenIssuer, TokenIssuerKeyStore,
                       TokenUtils)

BASEDIR: typing.Final = os.path.dirname(os.path.realpath(__file__))

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


keyfile = pathlib.Path(os.path.join(BASEDIR, 'signingkey.txt'))
signer: typing.Final = AsyncJWTHelper(app.logger, key=TokenUtils.read_signing_key(keyfile))
keystore: typing.Final = TokenIssuerKeyStore()
issuer = TokenIssuer(app, signer, keystore)


@app.before_serving
async def _before_serving() -> None:
    pass


@app.after_serving
async def _after_serving() -> None:
    keystore.clear()
    pass


if __name__ == "__main__":

    network_access_token = asyncio.run(issuer.generate_access_token(datetime.timedelta(days=7), ipaddress.ip_network("192.168.0.0/24")))
    print(f'{network_access_token=}')

    with open(os.path.join(BASEDIR, 'clientkeys.txt')) as ifp:
        for ifpline in ifp.readlines():
            pubkey_type, pubkey_data = str(ifpline.strip()).split()[:2]
            keystore.add(" ".join([pubkey_type, pubkey_data]))

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
