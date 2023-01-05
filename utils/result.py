""" Generic classes for return values with multiple common attributes. """

from typing import Any


class Result:
    """
    Generic class for function results.

    Not a dataclass to preserve Python 3.6 compatibility.
    """
    success: bool
    result: Any
    message: str

    def __init__(self, success, result, message):
        self.success = success
        self.result = result
        self.message = message


class SuccessResult(Result):
    """ Generic class for successful function results. """
    def __init__(self, result):
        super().__init__(success=True, result=result, message=None)


class FailureResult(Result):
    """ Generic class for failed function results. """
    def __init__(self, message):
        super().__init__(success=False, result=None, message=message)
