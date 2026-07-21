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

import json
import multiprocessing
import sys
import unittest
from types import ModuleType


def _install_standalone_test_stubs():
    encryption_helper = ModuleType("encryption_helper")
    encryption_helper.decrypt = lambda value, asset_id: value
    sys.modules.setdefault("encryption_helper", encryption_helper)

    urllib3 = ModuleType("urllib3")
    urllib3.disable_warnings = lambda: None
    sys.modules.setdefault("urllib3", urllib3)
    sys.modules.setdefault("requests", ModuleType("requests"))
    sys.modules.setdefault("simplejson", json)

    slack_bolt = ModuleType("slack_bolt")
    slack_bolt.App = object
    slack_bolt_adapter = ModuleType("slack_bolt.adapter")
    slack_bolt_socket_mode = ModuleType("slack_bolt.adapter.socket_mode")
    slack_bolt_socket_mode.SocketModeHandler = object
    sys.modules.setdefault("slack_bolt", slack_bolt)
    sys.modules.setdefault("slack_bolt.adapter", slack_bolt_adapter)
    sys.modules.setdefault("slack_bolt.adapter.socket_mode", slack_bolt_socket_mode)


_install_standalone_test_stubs()

from slack_bot_standalone import SlackBot


def _bot() -> SlackBot:
    return SlackBot(bot_token="bot", socket_token="socket", bot_id="id")


def _sanitize_malformed_link(result_queue):
    result_queue.put(_bot()._sanitize("get_container > <"))


class SlackBotStandaloneTests(unittest.TestCase):
    def test_soar_certificate_verification_defaults_to_enabled(self):
        self.assertTrue(_bot().verify)

    def test_sanitize_unwraps_slack_links(self):
        self.assertEqual(_bot()._sanitize("open <https://example.com|example>"), "open example")

    def test_sanitize_returns_when_closing_bracket_precedes_opening_bracket(self):
        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue()
        process = context.Process(target=_sanitize_malformed_link, args=(result_queue,))
        process.start()
        process.join(timeout=2)

        try:
            self.assertFalse(process.is_alive(), "Sanitizing malformed Slack links must terminate")
            self.assertEqual(process.exitcode, 0)
            self.assertEqual(result_queue.get(timeout=1), "get_container > <")
        finally:
            if process.is_alive():
                process.terminate()
                process.join()
            result_queue.close()
