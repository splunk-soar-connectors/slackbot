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
from argparse import ArgumentParser

import slack_bot_consts as constants
from commands.command import Command

HELP_MESSAGE = """
usage:

list <actions|containers|playbooks>

arguments:
  --help        show this help message and exit
  object        name of object to list, can be 'actions', 'containers', or 'playbooks'

For example:
    @<bot_username> list containers
  or
    @<bot_username> list actions
  or
    @<bot_username> list playbooks
"""


class ListCommand(Command):
    """ List Command. """

    HELP_MESSAGE = HELP_MESSAGE

    def _create_parser(self):
        self.list_parser = ArgumentParser(exit_on_error=False, add_help=False)
        self.list_parser.add_argument('--help', dest='aid', action='store_true')
        self.list_parser.add_argument('listee', choices=['actions', 'containers'])

    def parse(self, command):
        """ Parse the specified command string. """
        parse_success, result = self._get_parsed_args(command)

        if not parse_success:
            return False, result

        parsed_args = result

        message_list = []
        if parsed_args.listee == 'actions':
            sorted_actions = list(self.slack_bot.action_dict.keys())
            sorted_actions.sort()

            for action in sorted_actions:
                message_list.append(str(action))

            message_list.append('')
            message_list.append('For more info on an action, try "act <action_name>"')

        elif parsed_args.listee == 'containers':
            try:
                query_parameters = {}
                query_parameters['page_size'] = 0
                get_containers_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER, query_parameters=query_parameters)
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

        return True, '\n'.join(message_list)

    def execute(self, request_body, channel):
        """ Execute the specified request body for the command and post the result on the specified channel. """
        return request_body
