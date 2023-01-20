# File: get_action.py
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


class GetActionCommand(Command):
    """ Get Action Command. """

    COMMAND_NAME = 'get_action'
    COMMAND_DESCRIPTION = 'Query for actions. Only actions matching ALL specified filters will be returned (AND)'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('--name', help='The action name to filter on. Case insensitive')
        parser.add_argument('--app', help='The app name to filter on. Case insensitive')
        parser.add_argument('--type', dest='action_type', help='The action type to filter on. Case insensitive')
        parser.add_argument('--sort-by', default='name', choices=['name', 'type'], type=str.lower,
                            help='The sort key to use')
        parser.add_argument('--sort-order', default='asc', choices=['asc', 'desc'], type=str.lower,
                            help='The sort order to use')
        parser.add_argument('--limit', default=10, type=int,
                            help='The number of results to show. Specify 0 to show all results')
        parser.add_argument('--short', default=False, action='store_true',
                            help='If specified, prints the output in a compact format')

    def _query_actions(self, parsed_args) -> Result:
        sort_filter = parsed_args.sort_by
        if sort_filter == 'name':
            sort_filter = 'action'

        query_parameters = {
            'page_size': parsed_args.limit,
            'sort': sort_filter,
            'order': parsed_args.sort_order,
            '_filter_action__icontains': self.slack_bot._create_query_string(getattr(parsed_args, 'name', None)),
            '_filter_app__name__icontains': self.slack_bot._create_query_string(getattr(parsed_args, 'app', None)),
            '_filter_type__icontains': self.slack_bot._create_query_string(getattr(parsed_args, 'action_type', None)),
        }
        # Remove empty filters
        query_parameters = {key: value for key, value in query_parameters.items() if value is not None}

        try:
            get_action_request = self.slack_bot._soar_get(constants.SoarRestEndpoint.APP_ACTION,
                                                             query_parameters=query_parameters)
            get_action_request.raise_for_status()
            action_info = get_action_request.json()
        except Exception as e:
            return FailureResult(f'Failed to query for actions: {e}')

        return SuccessResult(action_info)

    def execute(self, parsed_args) -> str:
        """ Execute the command with the specified arguments and return a message of the result. """
        action_info_result = self._query_actions(parsed_args)
        if not action_info_result.success:
            return action_info_result.message
        action_info = action_info_result.result

        num_actions_found = int(action_info['count'])
        actions_suffix = 's' if num_actions_found != 1 else ''

        message_list = []
        message_list.append(f'Found {num_actions_found} matching action{actions_suffix}:')
        for action in action_info['data']:
            action_name = None
            try:
                action_name = action['action']
                action_description = action['description']
                action_type = action['type']
                app_id = action['app']
                if parsed_args.short:
                    short_message_list = [
                        f'Name: {action_name}'.ljust(20),
                        f'App ID: {app_id}'.ljust(14),
                        f'Description: {action_description}',
                    ]
                    message_list.append(' '.join(short_message_list))
                else:
                    message_list.append(f'Name: {action_name}')
                    message_list.append(f'Type: {action_type}')
                    message_list.append(f'App ID: {app_id}')
                    message_list.append(f'Description: {action_description}')
                    message_list.append('')
            except Exception:
                failure_message = f'Could not parse action info for action {action_name}'
                logging.exception(failure_message)
                message_list.append(failure_message)

        return '\n'.join(message_list)
