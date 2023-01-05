# File: get_container.py
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


class GetContainerCommand(Command):
    """ Get Container Command. """

    COMMAND_NAME = 'get_container'

    @staticmethod
    def _create_tags_message(tags) -> str:
        return ', '.join(f'"{tag}"' for tag in tags)

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('--container', help='The container ID to retrieve')
        parser.add_argument('--tags', nargs='+', help='The tags to filter on')
        parser.add_argument('--name', help='The container name to filter on')
        parser.add_argument('--label', help='The container label to filter on')
        parser.add_argument('--status', help='The container status to filter on')
        parser.add_argument('--owner', help='The container owner to filter on')

    def check_authorization(self) -> bool:
        """ Return True if authorized to run command. """
        if self.slack_bot.permit_container:
            logging.debug('**Command: "%s" is permitted', self.COMMAND_NAME)
            return True

        logging.debug('**Command: "%s" is not permitted', self.COMMAND_NAME)
        return False

    def execute(self, parsed_args):
        """ Execute the command with the specified arguments and return a message of the result. """
        container = parsed_args.container
        tags = parsed_args.tags

        # Perform on XOR to make sure only one of the arguments is set
        if (container is not None) == (tags is not None):
            return self.HELP_MESSAGE

        if container:
            container_info = {}
            try:
                container = int(container)
            except Exception:
                try:
                    return f'Could not parse container ID: {container}'
                except Exception:
                    return 'Could not parse given container ID'

            try:
                query_parameters = {}
                get_container_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER,
                                                                 path_postfix=f'/{container}',
                                                                 query_parameters=query_parameters)
                container_info = get_container_request.json()
            except Exception as e:
                return f'Could not retrieve container data. Could not connect to REST endpoint: {e}'

            message = ''
            for key, value in container_info.items():
                if key == 'tags':
                    message += 'Tags: '
                    for tag in value:
                        message += f' "{tag}",'
                    message = message[:-1]
                    message += '\n'
                    continue

                try:
                    message += f'{key}: {value}\n'
                except Exception:
                    message += f'{key}: Value could not be parsed\n'

            return message

        if tags:
            container_dict = self.slack_bot._create_container_dict()

            if container_dict is None:
                return 'Could not get containers, error contacting the REST endpoint'

            if not container_dict:
                return 'Found no containers on the Phantom instance'

            bad_tags = []
            container_list = []

            for tag in tags:

                if tag not in container_dict:
                    bad_tags.append(tag)
                    continue

                container_list += container_dict[tag]

            container_list = list(set(container_list))

            num_containers = len(container_list)

            message_list = []

            containers_suffix = 's' if num_containers != 1 else ''
            message_list.append(f'Found {num_containers} container{containers_suffix} matching specified tags:')
            message_list.append('')

            for container in container_list:

                try:
                    query_parameters = {
                        'page_size': 0,
                        'sort': 'id',
                        'order': 'desc',
                    }
                    get_container_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER,
                                                                     path_postfix=f'/{container}',
                                                                     query_parameters=query_parameters)

                    info = get_container_request.json()
                except Exception as e:
                    logging.exception(f'Could not retrieve container data for container {container}')
                    message_list.append(f'Could not retrieve container data for container {container}: {e}')
                    message_list.append('')

                try:
                    message_list.append(f'Name: {info["name"]}')
                    message_list.append(f'ID: {info["id"]}')
                    message_list.append(f'Label: {info["label"]}')
                    message_list.append(f'Tags: {self._create_tags_message(info["tags"])}')
                except Exception:
                    message_list.append(f'Could not parse container info for container {container}')

                message_list.append('')

            if bad_tags:
                message_list.append(f'Tags with no results: {self._create_tags_message(bad_tags)}')

            return '\n'.join(message_list)
