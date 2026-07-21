# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from slack_bot_standalone import SlackBot


def _bot() -> SlackBot:
    return SlackBot(bot_token="bot", socket_token="socket", bot_id="id")


def test_soar_certificate_verification_defaults_to_enabled():
    assert _bot().verify is True


def test_sanitize_unwraps_slack_links():
    assert _bot()._sanitize("open <https://example.com|example>") == "open example"


def test_sanitize_returns_when_closing_bracket_precedes_opening_bracket():
    assert _bot()._sanitize("get_container > <") == "get_container > <"
