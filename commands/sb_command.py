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
import logging

import slack_bot_consts as constants
from slack_bot_enums import CommandPermission


class Command:
    """ Slack Bot command base class. """

    COMMAND_NAME: str = None
    COMMAND_DESCRIPTION: str = None

    def __init__(self, slack_bot, channel):
        self.slack_bot = slack_bot
        self.channel = channel

        if self.COMMAND_NAME is None:
            raise ValueError(f'COMMAND_NAME must be specified for the command {self.__class__.__name__}.')

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        raise NotImplementedError

    def check_authorization_and_execute(self, parsed_args) -> str:
        """
        Check authorization and execute the command.

        Return a message with the result.
        """
        if not self.check_authorization():
            return constants.SLACK_BOT_ERROR_COMMAND_NOT_PERMITTED

        return self.execute(parsed_args)

    def check_authorization(self) -> bool:
        """ Return True if authorized to run command. """
        expected_permission = CommandPermission[self.COMMAND_NAME.upper()]
        if self.slack_bot.command_permissions[expected_permission]:
            logging.debug('**Command: "%s" is permitted', self.COMMAND_NAME)
            return True

        logging.debug('**Command: "%s" is not permitted', self.COMMAND_NAME)
        return False

    def execute(self, parsed_args) -> str:
        """ Execute the specified  the command using the specified arguments and return a message with the result. """
        raise NotImplementedError
