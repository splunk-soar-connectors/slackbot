# File: test_sb_query.py
#
# Copyright (c) 2026 Splunk Inc.
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
from urllib.parse import parse_qs

from utils.sb_query import create_query_string


def test_create_query_string_encodes_parameter_delimiters():
    injected_value = '"app-id"&page_size=0&_filter_id__in=attacker'

    query_string = create_query_string({"_filter_name": injected_value})

    assert "%26" in query_string
    assert "%3D" in query_string
    assert parse_qs(query_string.removeprefix("?")) == {"_filter_name": [injected_value]}


def test_create_query_string_preserves_list_parameters():
    query_string = create_query_string({"_filter_id__in": ["first", "second"], "page_size": 0})

    assert parse_qs(query_string.removeprefix("?")) == {
        "_filter_id__in": ["first", "second"],
        "page_size": ["0"],
    }


def test_create_query_string_handles_empty_parameters():
    assert create_query_string({}) == ""
    assert create_query_string(None) == ""
