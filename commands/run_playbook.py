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

from argparse import ArgumentParser

import slack_bot_consts as constants
from commands.command import Command

HELP_MESSAGE = """
usage:

run_playbook <--repo REPO PLAYBOOK_NAME | PLAYBOOK_ID> CONTAINER_ID

required arguments:
  PLAYBOOK_NAME      Name of the playbook to run (Required if repo argument is included)
  PLAYBOOK_ID        ID of the playbook to run (Required if no repo argument is included)
  CONTAINER_ID      ID of container to run playbook on

optional arguments:
  --help        show this help message and exit
  --repo REPO   Name of the repo the playbook is in (required if playbook
                argument is a name, and not an ID)

For example:
    @<bot_username> run_playbook --repo community invesigate 25
  or
    @<bot_username> run_playbook 1 25
"""


class RunPlaybookCommand(Command):
    """ Run Playbook Command. """

    HELP_MESSAGE = HELP_MESSAGE

    def _create_parser(self):
        playbook_parser = ArgumentParser(exit_on_error=False)
        playbook_parser.add_argument('--repo', dest='repo',
                                     help='Name of the repo the playbook is in '
                                          '(required if playbook argument is a name, and not an ID)')
        playbook_parser.add_argument('playbook', help='Name or ID of the playbook to run')
        playbook_parser.add_argument('container', help='ID of container to run playbook on')
        return playbook_parser

    def parse(self, command):
        """ Parse the specified command string. """
        parse_success, result = self._get_parsed_args(command)

        if not parse_success:
            return False, result

        parsed_args = result

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

    def execute(self, request_body, channel):
        """ Execute the specified request body for the command and post the result on the specified channel. """

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

        self.slack_bot._post_message(f'Container URL: {container_url}', channel, code_block=False)

        return f'Playbook: {playbook_id}\nPlaybook run ID: {resp["playbook_run_id"]}\nPlaybook queueing result: Playbook run successfully queued'
