import logging


def debugcall(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        log = logging.getLogger(fn.__name__)
        log.info('Entering %s' % fn.__name__)

        out = fn(*args, **kwargs)

        log.info('Exiting %s' % fn.__name__)
        return out

    return wrapper
