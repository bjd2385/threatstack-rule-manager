from typing import Type, Callable, Any

import logging

from functools import wraps
from time import sleep


def retry(exc: Type[Exception], tries: int =3, delay: float =2.0) -> Callable:
    """
    A general request retry decorator with optional time delay.

    Args:
        exc: exception to catch and retry on.
        tries: number of times to retry the wrapped function call. When `0`, retries indefinitely.
        delay: positive wait period.

    Raises:
        A RetryLimitExceeded exception in the event that the call could not be completed after the
        allotted number of attempts.

    Returns:
        Either the result of a successful function call (be it via retrying or not).
    """
    if tries < 0 or delay < 0:
        raise ValueError('Expected positive `tries` and `delay` values, received: '
                         f'tries {tries}, delay {delay}')

    def _f(f: Callable) -> Callable:

        class RetryLimitExceeded(OSError):
            pass

        @wraps(f)
        def new_f(*args: Any, **kwargs: Any) -> Any:
            res: Any = None

            def call() -> bool:
                nonlocal res
                try:
                    res = f(*args, **kwargs)
                    return True
                except exc as msg:
                    logging.info(f'Retrying: {msg} ~ {res}')
                    sleep(delay)
                    return False

            if tries > 0:
                for _ in range(tries):
                    if call():
                        return res
                else:
                    raise RetryLimitExceeded(
                        f'Exceeded max of {tries} tries. Raise the delay limit of {delay} or number of tries'
                    )
            else:
                while not call():
                    pass
                else:
                    return res

        return new_f

    return _f