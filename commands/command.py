# File: command.py
#
# Copyright (c) 2023 Splunk Inc.
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


class Command():
    """ Slack Bot command base class. """

    HELP_MESSAGE = None

    def __init__(self, slack_bot):
        self.slack_bot = slack_bot

        if self.HELP_MESSAGE is None:
            raise Exception('A help message must be specified in HELP_MESSAGE')

        self.command_parser = self._create_parser()

    def _create_parser(self):
        """ Initialize the command parser. """
        raise NotImplementedError

    def _get_parsed_args(self, command):
        """
        Parse the specified command string.

        Returns true and the parsed_args if successful.
        Returns false and a help message if failed.
        """
        try:
            parsed_args = self.command_parser.parse_args(command)
        except:  # noqa: We also want to catch SystemError exceptions
            return False, self.HELP_MESSAGE

        return True, parsed_args

    def parse(self, command):
        """ Parse the specified command string. """
        raise NotImplementedError

    def execute(self, request_body, channel):
        """ Execute the specified request body for the command and post the result on the specified channel. """
        raise NotImplementedError
