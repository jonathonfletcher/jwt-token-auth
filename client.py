import logging
import colorlog

from support import TokenClient


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
    logger.addHandler(handler)

    o = TokenClient('SHA256:cQKF3Vquko1VMT8b+DHtilunzY5EW3bcUctBcSNBhw4')
    token = o.access_token
    logger.info(f'{token=!s}')
    # token = o._get_decoded_token(access_token)
    print(f'{token.iat=}')
    print(f'{token.exp=}')
    print(f'{token.ipn=}')
    print(f'{o.verify(token)=}')
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
