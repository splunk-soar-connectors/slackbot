# File: run_playbook.py
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

import slack_bot_consts as constants
from commands.command import Command


class RunPlaybookCommand(Command):
    """ Run Playbook Command. """

    COMMAND_NAME = 'run_playbook'

    def configure_parser(self, parser) -> None:
        """ Configure the parser for this command. """
        parser.add_argument('--repo',
                            help='Name of the repo the playbook is in '
                                '(required if playbook argument is a name, and not an ID)')
        parser.add_argument('playbook', help='Name or ID of the playbook to run')
        parser.add_argument('container', help='ID of container to run playbook on')

    def _process_args(self, parsed_args):
        request_body = {}
        request_body['run'] = True
        request_body['container_id'] = parsed_args.container

        # Check to see if its a numeric ID
        try:
            playbook = int(parsed_args.playbook)
        except Exception:
            if not parsed_args.repo:
                return False, 'repo argument is required when supplying playbook name instead of playbook ID'

            playbook = f'{parsed_args.repo}/{parsed_args.playbook}'

        request_body['playbook_id'] = playbook

        return True, request_body

    def execute(self, parsed_args) -> str:
        """ Execute the command with the specified arguments and return a message of the result. """
        success, result = self._process_args(parsed_args)
        if not success:
            return result

        request_body = result
        try:
            playbook_run_request = self.slack_bot._soar_post(constants.SoarRestEndpoint.PLAYBOOK_RUN,
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

        return f'Playbook: {playbook_id}\nPlaybook run ID: {resp["playbook_run_id"]}\nPlaybook queueing result: Playbook run successfully queued'
