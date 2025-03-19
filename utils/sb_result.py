# File: sb_result.py
#
# Copyright (c) 2023-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
"""Generic classes for return values with multiple common attributes."""

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
    """Generic class for successful function results."""

    def __init__(self, result):
        super().__init__(success=True, result=result, message=None)


class FailureResult(Result):
    """Generic class for failed function results."""

    def __init__(self, message):
        super().__init__(success=False, result=None, message=message)
