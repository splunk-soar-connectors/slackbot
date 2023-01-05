# File: list.py
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
from commands.command import Command


class ListCommand(Command):
    """ List Command. """

    COMMAND_NAME = 'list'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('listee', choices=['actions', 'containers', 'playbooks'])

    def check_authorization(self) -> bool:
        """ Return True if authorized to run command. """
        if self.slack_bot.permit_list:
            logging.debug('**Command: "%s" is permitted', self.COMMAND_NAME)
            return True

        logging.debug('**Command: "%s" is not permitted', self.COMMAND_NAME)
        return False

    def execute(self, parsed_args) -> str:
        """ Execute the command with the specified arguments and return a message of the result. """
        message_list = []
        if parsed_args.listee == 'actions':
            sorted_actions = sorted(self.slack_bot.get_action_dict().keys())

            for action in sorted_actions:
                message_list.append(str(action))

            message_list.append('')
            message_list.append('For more info on an action, try "act <action_name>"')

        elif parsed_args.listee == 'containers':
            try:
                query_parameters = {}
                query_parameters['page_size'] = 0
                get_containers_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER,
                                                                  query_parameters=query_parameters)
            except Exception as e:
                logging.exception('Failed to retrieve container data.')
                return False, f'Could not retrieve container data. Could not connect to REST endpoint: {e}'

            try:
                sorted_containers = sorted(get_containers_request.json()['data'], key=lambda container: container['id'])
            except Exception as e:
                logging.exception('Failed to parse retrieved container data.')
                return False, f'Could not parse container data: {e}'

            for container in sorted_containers:
                try:
                    message_list.append(f'ID: {container["id"]}'.ljust(10) + f'Name: {container["name"]}')
                except Exception:
                    message_list.append('Container info could not be parsed')

            message_list.append('')
            message_list.append('For more information on a container, try "get_container <container_id>"')

        return '\n'.join(message_list)
