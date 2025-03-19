# File: sb_debug.py
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

import os

from commands.sb_command import Command


class DebugCommand(Command):
    """Debug Command."""

    COMMAND_NAME = "debug"
    COMMAND_DESCRIPTION = "Print debug info pertaining to the bot running on SOAR"

    def configure_parser(self, parser) -> None:
        """Configure the parser for this command."""

    def check_authorization(self) -> bool:
        """Return True if authorized to run command."""
        # No gating permission for this command.
        return True

    def execute(self, parsed_args) -> str:  # pylint: disable=unused-argument
        """Execute the command with the specified arguments and return a message of the result."""
        debug_info = []
        debug_info.append("Slack Bot Debug Info")
        debug_info.append(f"Host: {self.slack_bot.base_url}")
        debug_info.append(f"PID: {os.getpid()}")
        debug_info.append(f"SOAR App Version: {self.slack_bot.app_version}")
        return "\n".join(debug_info)
