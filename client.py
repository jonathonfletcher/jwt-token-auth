import logging

import colorlog

from tokenauth import Token, TokenClient

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler):
            logger.removeHandler(handler)
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
    logger.addHandler(handler)

    tc = TokenClient(logger=logger)
    if tc.use('SHA256:YFJs7vPDdh5ygDn6Hl2MwXpOwaYwUgLA3Ch93sjan7E'):
        token = tc.access_token
        logger.info(f'{token=!s}')
        if isinstance(token, Token):
            print(f'{token.iat=}')
            print(f'{token.exp=}')
            print(f'{token.ipn=}')
            print(f'{token.valid=}')
            print(f'{tc.verify(token)=}')
    pass
