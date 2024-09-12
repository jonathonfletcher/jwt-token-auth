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
    print(f'{token.iat=}')
    print(f'{token.exp=}')
    print(f'{token.ipn=}')
    print(f'{token.valid=}')
    print(f'{o.verify(token)=}')
    pass
