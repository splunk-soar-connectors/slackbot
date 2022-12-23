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
from argparse import ArgumentParser

import slack_bot_consts as constants
from commands.command import Command

HELP_MESSAGE = """
usage:

get_container <--container CONTAINER_ID | --tags TAG [TAG]*>

arguments:
  --help                    show this help message and exit
  --container CONTAINER     ID of the container to retrieve
  --tags TAG [TAG]*         List of tags of containers to retrieve

Only one of --container or --tags flags can be included at once

For example:
    @<bot_username> get_container --container 16
  or
    @<bot_username> get_container --tags tag1 tag2 tag3
"""


class GetContainerCommand(Command):
    """ Get Container Command. """

    HELP_MESSAGE = HELP_MESSAGE

    def _create_parser(self):
        container_parser = ArgumentParser(exit_on_error=False)
        container_parser.add_argument('--container')
        container_parser.add_argument('--tags', nargs='+')
        return container_parser

    def parse(self, command):
        """ Parse the specified command string. """
        parse_success, result = self._get_parsed_args(command)

        if not parse_success:
            return False, result

        parsed_args = result

        container = parsed_args.container
        tags = parsed_args.tags

        # Perform on XOR to make sure only one of the arguments is set
        if (container is not None) == (tags is not None):
            return False, self.HELP_MESSAGE

        def create_tags_message(tags):
            return ', '.join(f'"{tag}"' for tag in tags)

        if container:
            container_info = {}
            try:
                container = int(container)
            except Exception:
                try:
                    return False, f'Could not parse container ID: {container}'
                except Exception:
                    return False, 'Could not parse given container ID'

            try:
                query_parameters = {}
                get_container_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER,
                                                                 path_postfix=f'/{container}',
                                                                 query_parameters=query_parameters)
                container_info = get_container_request.json()
            except Exception as e:
                return False, f'Could not retrieve container data. Could not connect to REST endpoint: {e}'

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

            return True, message

        if tags:
            container_dict = self.slack_bot._create_container_dict()

            if container_dict is None:
                return False, 'Could not get containers, error contacting the REST endpoint'

            if not container_dict:
                return False, 'Found no containers on the Phantom instance'

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
                    query_parameters = {}
                    query_parameters['page_size'] = 0
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
                    message_list.append(f'Tags: {create_tags_message(info["tags"])}')
                except Exception:
                    message_list.append(f'Could not parse container info for container {container}')

                message_list.append('')

            if bad_tags:
                message_list.append(f'Tags with no results: {create_tags_message(bad_tags)}')

            return True, '\n'.join(message_list)

    def execute(self, request_body, channel):
        """ Execute the specified request body for the command and post the result on the specified channel. """
        return request_body
