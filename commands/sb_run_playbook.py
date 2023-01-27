# File: sb_run_playbook.py
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

from commands.sb_command import Command
from slack_bot_enums import SoarRestEndpoint
from utils.sb_result import FailureResult, Result, SuccessResult


class RunPlaybookCommand(Command):
    """ Run Playbook Command. """

    COMMAND_NAME = 'run_playbook'
    COMMAND_DESCRIPTION = 'Run a playbook'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('container', type=int, help='ID of container to run playbook on')
        playbook_group = parser.add_mutually_exclusive_group(required=True)
        playbook_group.add_argument('-n', '--name', help='Name of the playbook to run')
        playbook_group.add_argument('-i', '--id', dest='playbook_id', type=int,
                                    help='ID of the playbook to run')
        parser.add_argument('-r', '--repo',
                            help='Name of the repo the playbook is in '
                                 '(required if playbook argument is a name, and not an ID)')

    def _process_args(self, parsed_args) -> Result:
        request_body = {}
        request_body['run'] = True
        request_body['container_id'] = parsed_args.container

        playbook_id = getattr(parsed_args, 'playbook_id', None)
        if playbook_id is None:
            if not hasattr(parsed_args, 'repo'):
                return FailureResult('repo argument is required when supplying playbook name instead of playbook ID')
            playbook_id = f'{parsed_args.repo}/{parsed_args.name}'

        request_body['playbook_id'] = playbook_id
        return SuccessResult(request_body)

    def execute(self, parsed_args) -> str:
        """ Execute the command with the specified arguments and return a message of the result. """
        request_body_result = self._process_args(parsed_args)
        if not request_body_result.success:
            return request_body_result.message

        request_body = request_body_result.result
        try:
            playbook_run_request = self.slack_bot._soar_post(SoarRestEndpoint.PLAYBOOK_RUN,
                                                             body=request_body)
            resp = playbook_run_request.json()
        except Exception as e:
            return f'Failed to run playbook: Could not connect to Phantom REST endpoint: {e}'

        if resp.get('failed', False):
            return f'Failed to run playbook: {resp.get("message", "unknown error")}'

        run_id = resp.get('playbook_run_id')

        if not run_id:
            return 'Failed to run playbook: Could not get playbook run ID'

        container_id = request_body.get('container_id', '')
        playbook_id = request_body.get('playbook_id', '')

        container_url = f'{self.slack_bot.phantom_url}mission/{container_id}'

        self.slack_bot._post_message(f'Container URL: {container_url}', self.channel, code_block=False)

        return '\n'.join([f'Playbook: {playbook_id}',
                          f'Playbook run ID: {run_id}',
                          'Playbook queueing result: Playbook run successfully queued'])
