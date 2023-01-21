# File: get_playbook.py
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

from commands.command import Command
from slack_bot_enums import SoarRestEndpoint
from utils.result import FailureResult, Result, SuccessResult


class GetPlaybookCommand(Command):
    """ Get Playbook Command. """

    COMMAND_NAME = 'get_playbook'
    COMMAND_DESCRIPTION = 'Query for playbooks. Only playbooks matching ALL specified filters will be returned (AND)'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('--name', help='The playbook name to filter on. Case insensitive')
        parser.add_argument('--status', choices=['active', 'inactive', 'draft'], type=str.lower,
                            help='The playbook status to filter on')
        parser.add_argument('--type', dest='playbook_type',
                            help='The playbook type to filter on. Case insensitive')
        parser.add_argument('--repo', help='The repo name to filter on')
        parser.add_argument('--sort-by', default='name', choices=['name', 'type'], type=str.lower,
                            help='The sort key to use')
        parser.add_argument('--sort-order', default='asc', choices=['asc', 'desc'], type=str.lower,
                            help='The sort order to use')
        parser.add_argument('--limit', default=10, type=int,
                            help='The number of results to show. Specify 0 to show all results')
        parser.add_argument('-s', '--short', default=False, action='store_true',
                            help='If specified, prints the output in a compact format')

    def _query_playbooks(self, parsed_args) -> Result:
        status_arg = getattr(parsed_args, 'status', None)
        active_filter = None
        draft_filter = None
        if status_arg == 'active':
            active_filter = True
        elif status_arg == 'inactive':
            active_filter = False
        elif status_arg == 'draft':
            draft_filter = True

        sort_filter = parsed_args.sort_by
        if sort_filter == 'type':
            sort_filter = 'playbook_type'

        query_parameters = {
            'page_size': parsed_args.limit,
            'sort': sort_filter,
            'order': parsed_args.sort_order,
            '_filter_name__icontains': self.slack_bot._create_query_string(getattr(parsed_args, 'name', None)),
            '_filter_active': active_filter,
            '_filter_draft_mode': draft_filter,
            '_filter_playbook_type__icontains':
                self.slack_bot._create_query_string(getattr(parsed_args, 'playbook_type', None)),
            '_filter_scm__name': self.slack_bot._create_query_string(getattr(parsed_args, 'repo', None)),
        }
        # Remove empty filters
        query_parameters = {key: value for key, value in query_parameters.items() if value is not None}

        try:
            get_playbook_request = self.slack_bot._soar_get(SoarRestEndpoint.PLAYBOOK,
                                                            query_parameters=query_parameters)
            get_playbook_request.raise_for_status()
            playbook_info = get_playbook_request.json()
        except Exception as e:
            return FailureResult(f'Failed to query for playbooks: {e}')

        return SuccessResult(playbook_info)

    def execute(self, parsed_args) -> str:
        """ Execute the command with the specified arguments and return a message of the result. """
        playbook_info_result = self._query_playbooks(parsed_args)
        if not playbook_info_result.success:
            return playbook_info_result.message
        playbook_info = playbook_info_result.result

        num_playbooks_found = int(playbook_info['count'])
        playbooks_suffix = 's' if num_playbooks_found != 1 else ''

        message_list = []
        message_list.append(f'Found {num_playbooks_found} matching playbook{playbooks_suffix}:')
        for playbook in playbook_info['data']:
            playbook_id = None
            try:
                playbook_name = playbook['name']
                playbook_version = playbook['version']

                playbook_type = playbook['playbook_type']
                if playbook_type:
                    playbook_type = playbook_type.capitalize()

                playbook_is_active = playbook['active']
                playbook_is_draft = playbook['draft_mode']
                if playbook_is_draft:
                    playbook_status = 'Draft'
                elif playbook_is_active:
                    playbook_status = 'Active'
                else:
                    playbook_status = 'Inactive'

                if parsed_args.short:
                    message_list.append(f' Type: {playbook_type}'.ljust(20) +
                                        f' Name: {playbook_name}' )
                else:
                    message_list.append(f'Name: {playbook_name}')
                    message_list.append(f'Version: {playbook_version}')
                    message_list.append(f'Type: {playbook_type}')
                    message_list.append(f'Status: {playbook_status}')
                    message_list.append('')
            except Exception:
                failure_message = f'Could not parse playbook info for playbook {playbook_id}'
                logging.exception(failure_message)
                message_list.append(failure_message)

        return '\n'.join(message_list)
