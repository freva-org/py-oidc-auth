"""Exceptions raised by py oidc auth.

This package raises a single public exception type, :class:`InvalidRequest`.
Integrations for web frameworks typically translate it into framework specific
HTTP errors.

The exception is designed to be simple to map to an HTTP response.
It carries an HTTP status code and a human readable detail message.

Example
-------
.. code-block:: python

    from py_oidc_auth.exceptions import InvalidRequest

    raise InvalidRequest(status_code=401, detail="Not authenticated")

"""

import logging

logger = logging.getLogger("py-oidc-auth.requests")


class InvalidRequest(Exception):
    """An error that can be represented as an HTTP response.

    :param status_code: HTTP status code to return to the client.
    :param detail: Human readable error message.

    The exception is used throughout the core implementation and the framework
    adapters.

    Example
    -------
    .. code-block:: python

        try:
            ...
        except InvalidRequest as exc:
            return {"status": exc.status_code, "detail": exc.detail}

    """

    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

    def log_traceback(self) -> None:
        """Log a traceback with a warning."""
        logger.warning(
            "Invalid Request with %i: %s",
            self.status_code,
            self.detail,
            exc_info=self,
        )
