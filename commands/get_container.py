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
from utils.result import FailureResult, Result, SuccessResult


class GetContainerCommand(Command):
    """ Get Container Command. """

    COMMAND_NAME = 'get_container'
    COMMAND_DESCRIPTION = 'Query for containers. Only containers matching ALL specified filters will be returned (AND)'

    @staticmethod
    def _create_tags_message(tags) -> str:
        return ', '.join(f'"{tag}"' for tag in tags)

    @staticmethod
    def _create_query_string(value) -> str:
        if value is None:
            return None

        return f'"{value}"'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """

        ored_list_help = 'Space-separated. Any matches will be included (OR)'
        parser.add_argument('--container', type=int, help='The container ID to filter on')
        parser.add_argument('--name', help='The container name to filter on. Case insensitive')
        parser.add_argument('--tags', nargs='*',
                            help=f'The tags to filter on. {ored_list_help}')
        parser.add_argument('--labels', nargs='*',
                            help=f'The container labels to filter on. {ored_list_help}')
        parser.add_argument('--statuses', nargs='*',
                            help=f'The container statuses to filter on. {ored_list_help}')
        parser.add_argument('--owners', nargs='*',
                            help=f'The container owners to filter on. {ored_list_help}')
        parser.add_argument('--sort-by', default='id', choices=['id', 'name'],
                            help='The sort key to use')
        parser.add_argument('--sort-order', default='desc', choices=['asc', 'desc'],
                            help='The sort order to use')
        parser.add_argument('--limit', default=10, type=int,
                            help='The number of results to show. Specify 0 to show all results')

    def check_authorization(self) -> bool:
        """ Return True if authorized to run command. """
        if self.slack_bot.permit_container:
            logging.debug('**Command: "%s" is permitted', self.COMMAND_NAME)
            return True

        logging.debug('**Command: "%s" is not permitted', self.COMMAND_NAME)
        return False

    def _query_containers(self, parsed_args) -> Result:
        query_parameters = {
            'page_size': parsed_args.limit,
            'sort': parsed_args.sort_by,
            'order': parsed_args.sort_order,
            '_filter_id': getattr(parsed_args, 'container', None),
            '_filter_name__icontains': self._create_query_string(getattr(parsed_args, 'name', None)),
            '_filter_tags__has_any_keys': getattr(parsed_args, 'tags', None),
            '_filter_label__in': getattr(parsed_args, 'labels', None),
            '_filter_status__name__in': getattr(parsed_args, 'statuses', None),
            '_filter_owner_name__in': getattr(parsed_args, 'owners', None),
        }
        # Remove empty filters
        query_parameters = {key: value for key, value in query_parameters.items() if value is not None}

        try:
            get_container_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.CONTAINER,
                                                             query_parameters=query_parameters)
            get_container_request.raise_for_status()
            container_info = get_container_request.json()
        except Exception as e:
            return FailureResult(f'Failed to query for containers: {e}')

        return SuccessResult(container_info)

    def execute(self, parsed_args):
        """ Execute the command with the specified arguments and return a message of the result. """
        container_info_result = self._query_containers(parsed_args)
        if not container_info_result.success:
            return container_info_result.message
        container_info = container_info_result.result

        num_containers_found = int(container_info['count'])
        containers_suffix = 's' if num_containers_found != 1 else ''

        message_list = []
        message_list.append(f'Found {num_containers_found} matching container{containers_suffix}:')
        for container in container_info['data']:
            container_id = None
            try:
                container_id = container['id']
                message_list.append(f'Name: {container["name"]}')
                message_list.append(f'ID: {container_id}')
                message_list.append(f'Label: {container["label"]}')
                message_list.append(f'Tags: {self._create_tags_message(container["tags"])}')
            except Exception:
                message_list.append(f'Could not parse container info for container {container_id}')

            message_list.append('')

        return '\n'.join(message_list)
