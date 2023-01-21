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

from commands.sb_command import Command
from slack_bot_enums import SoarRestEndpoint
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
        verbosity_group = parser.add_mutually_exclusive_group(required=False)
        verbosity_group.add_argument('-s', '--short', default=False, action='store_true',
                                     help='If specified, prints the output in a compact format')
        verbosity_group.add_argument('-v', '--verbose', default=False, action='store_true',
                                     help='If specified, prints extra information about actions')

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
            get_action_request = self.slack_bot._soar_get(SoarRestEndpoint.APP_ACTION,
                                                          query_parameters=query_parameters)
            get_action_request.raise_for_status()
            action_info = get_action_request.json()
        except Exception as e:
            return FailureResult(f'Failed to query for actions: {e}')

        return SuccessResult(action_info)

    def _format_parameter(self, name, info) -> str:
        data_type = info.get('data_type', 'Unknown')
        required = info.get('required', False)
        description = info.get('description', '')
        lines = [
            f'  {name}',
            f'    Data Type: {data_type}',
            f'    Required: {required}',
            f'    Description: {description}',
        ]
        return '\n'.join(lines)

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

        app_ids = [info['app'] for info in action_info['data']]

        apps_by_app_id_result = self.slack_bot._get_apps_by_app_ids(app_ids)
        if not apps_by_app_id_result.success:
            return apps_by_app_id_result.message
        apps_by_app_id = apps_by_app_id_result.result

        assets_by_app_id_result = self.slack_bot._get_assets_by_app_ids(app_ids)
        if not assets_by_app_id_result.success:
            return assets_by_app_id_result.message
        assets_by_app_id = assets_by_app_id_result.result

        for action in action_info['data']:
            action_name = None
            try:
                action_name = action['action']
                action_description = action['description']
                action_type = action['type']
                app_id = action['app']
                app_name = apps_by_app_id[app_id]['name']
                asset_names = ', '.join(sorted(asset['name'] for asset in assets_by_app_id[app_id]))
                if parsed_args.short:
                    short_message_list = [
                        f'Name: {action_name}'.ljust(20),
                        f'App Name: {app_name}'.ljust(20),
                        f'Description: {action_description}',
                    ]
                    message_list.append(' '.join(short_message_list))
                else:
                    message_list.append(f'Name: {action_name}')
                    message_list.append(f'Type: {action_type}')
                    message_list.append(f'App Name: {app_name}')
                    message_list.append(f'App ID: {app_id}')
                    message_list.append(f'Description: {action_description}')
                    message_list.append(f'Assets: {asset_names}')
                    if parsed_args.verbose:
                        message_list.append('Parameters:')
                        for parameter_name, parameter_info in action.get('parameters', {}).items():
                            message_list.append(self._format_parameter(parameter_name, parameter_info))
                    message_list.append('')
            except Exception:
                failure_message = f'Could not parse action info for action {action_name}'
                logging.exception(failure_message)
                message_list.append(failure_message)

        return '\n'.join(message_list)
