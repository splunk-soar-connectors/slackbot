# File: slack_bot_standalone.py
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
import argparse
import logging
import os
import shlex
import sys
import tempfile
from collections import defaultdict
from io import StringIO
from pathlib import Path

import encryption_helper
import requests
import simplejson as json
import urllib3
from slack_bolt import App as slack_app
from slack_bolt.adapter.socket_mode import SocketModeHandler

from commands.sb_debug import DebugCommand
from commands.sb_get_action import GetActionCommand
from commands.sb_get_container import GetContainerCommand
from commands.sb_get_playbook import GetPlaybookCommand
from commands.sb_run_action import RunActionCommand
from commands.sb_run_playbook import RunPlaybookCommand
from slack_bot_consts import *
from slack_bot_enums import CommandPermission, SoarRestEndpoint
from utils.sb_result import FailureResult, Result, SuccessResult

urllib3.disable_warnings()


AVAILABLE_COMMANDS = sorted([
    DebugCommand,
    GetActionCommand,
    RunActionCommand,
    GetContainerCommand,
    GetPlaybookCommand,
    RunPlaybookCommand,
], key=lambda command: command.COMMAND_NAME)


def create_query_string(query_parameters):
    """ Create a query URL string from a query parameters dictionary. """
    if not query_parameters:
        return ''

    return '?' + '&'.join(f'{key}={value}' for key, value in query_parameters.items())


def dedupe(list_to_dedupe):
    """ Return the input list without any duplicates. """
    return list(dict.fromkeys(list_to_dedupe))


def _load_app_state(asset_id):
    """ This function is used to load the current state file.

    :param asset_id: asset_id
    :return: state: Current state file as a dictionary
    """
    asset_id = str(asset_id)
    if not asset_id or not asset_id.isalnum():
        logging.info('In _load_app_state: Invalid asset_id')
        return {}

    app_dir = os.path.dirname(os.path.abspath(__file__))

    state_file = f'{app_dir}/{asset_id}_state.json'
    real_state_file_path = os.path.realpath(state_file)

    if os.path.dirname(real_state_file_path) != app_dir:
        logging.info('In _load_app_state: Invalid asset_id')
        return {}

    state = {}
    try:
        with open(real_state_file_path, 'r') as state_file_obj:
            state_file_data = state_file_obj.read()
            state = json.loads(state_file_data)

    except Exception:
        logging.exception('In _load_app_state: Exception encountered.')

    logging.info('Loaded state: ', state)

    return state


def decrypt_state(asset_id, decrypt_var, token_name):
    """ Handle decryption of token.
    :param decrypt_var: Variable needs to be decrypted
    :return: decrypted variable
    """
    logging.debug(SLACK_BOT_DECRYPT_TOKEN.format(token_name))    # nosemgrep
    return encryption_helper.decrypt(decrypt_var, asset_id)


class SlackBot(object):

    def __init__(self, bot_token, socket_token, bot_id, base_url='https://127.0.0.1/', verify=False, auth_token='',
                 command_permissions=None, permitted_users='', auth_basic=(), app_version=''):
        """ This should be changed to some kind of load config thing """
        if command_permissions is None:
            command_permissions = {}

        self.app_version = app_version
        self.bot_token = bot_token
        self.socket_token = socket_token
        self.command_permissions = command_permissions
        self.permitted_users = permitted_users
        self.headers = {} if not auth_token else {'ph-auth-token': auth_token}
        self.cmd_start = f'<@{bot_id}>'
        self.auth = auth_basic
        self.verify = verify
        base_url += '/' if not base_url.endswith('/') else ''
        self.base_url = base_url
        self.phantom_url = base_url

    @staticmethod
    def _create_query_string(value) -> str:
        if value is None:
            return None

        return f'"{value}"'

    def _soar_get(self, endpoint: SoarRestEndpoint, query_parameters: dict = None, path_postfix: str = ''):
        """ Make a SOAR GET request. """
        url = f'{endpoint.url(self.base_url)}{path_postfix}{create_query_string(query_parameters)}'

        logging.debug('Sending GET request to SOAR URL: %s', url)
        return requests.get(url,
                            headers=self.headers,
                            auth=self.auth,
                            verify=self.verify,
                            timeout=SLACK_BOT_DEFAULT_TIMEOUT)

    def _soar_post(self, endpoint: SoarRestEndpoint, body: dict = None):
        """ Make a SOAR POST request. """
        url = endpoint.url(self.base_url)

        logging.debug('Sending POST request to SOAR URL: %s', url)
        return requests.post(url,
                             json=body,
                             headers=self.headers,
                             auth=self.auth,
                             verify=self.verify,
                             timeout=SLACK_BOT_DEFAULT_TIMEOUT)

    def _get_apps_by_app_ids(self, app_ids) -> Result:
        """ Return information for the specified app IDs. """
        app_ids = dedupe(app_ids)

        query_parameters = {
            'page_size': 0,
            '_filter_id__in': app_ids,
        }

        try:
            get_apps_request = self._soar_get(SoarRestEndpoint.APP,
                                              query_parameters=query_parameters)
            get_apps_request.raise_for_status()
            apps_info = get_apps_request.json()
        except Exception as e:
            failure_message = 'Failed to query for apps'
            logging.exception(failure_message)
            return FailureResult(f'{failure_message}: {e}')

        apps_by_id = {app_info['id']: app_info for app_info in apps_info['data']}
        return SuccessResult(apps_by_id)

    def _get_assets_by_app_ids(self, app_ids) -> Result:
        """ Return information for the specified app IDs. """
        app_ids = dedupe(app_ids)

        query_parameters = {
            'page_size': 0,
            '_filter_app__in': app_ids,
        }

        try:
            get_assets_request = self._soar_get(SoarRestEndpoint.ASSET,
                                                query_parameters=query_parameters)
            get_assets_request.raise_for_status()
            assets_info = get_assets_request.json()
        except Exception as e:
            failure_message = 'Failed to query for assets'
            logging.exception(failure_message)
            return FailureResult(f'{failure_message}: {e}')

        assets_by_app_id = defaultdict(list)
        for asset_info in assets_info['data']:
            assets_by_app_id[asset_info['app']].append(asset_info)
        return SuccessResult(assets_by_app_id)

    def _sanitize(self, input_string):
        """ Slack quotes use those fancy UTF-8 ones that flip based on what side they are on
          " Unforunately, those cause problems, so we replace them with normal quotes
          " I'm sure there are other UTF-8 characters that will need to be replaced like this,
          " but I haven't run into those yet
          " Emdashes (u2014) are another of those characters.
          " Slack also formats URLs annoyingly. A message containing a domain (eg google.com) will get changed to
          " <http://google.com/|google.com>. While a full URL (eg http://google.com) will get changed to
          " <http://google.com>. Need to look for both cases and get rid of the carrots and pipe (<|>).
          " And in the domain case, get rid of the URL.
        """

        sanitized_string = (
            input_string.replace('\u2014', '--')
                        .replace('\u2018', "'")
                        .replace('\u2019', "'")
                        .replace('\u201c', '"')
                        .replace('\u201d', '"')
        )

        while sanitized_string.find('<') > -1 and sanitized_string.find('>') > -1:
            left_index = sanitized_string.find('<')
            right_index = sanitized_string.find('>')
            pipe_index = sanitized_string.find('|')
            if left_index < pipe_index < right_index:
                url = sanitized_string[pipe_index + 1: right_index]
            else:
                url = sanitized_string[left_index + 1: right_index]
            sanitized_string = sanitized_string.replace(sanitized_string[left_index: right_index + 1], url, 1)

        return sanitized_string

    def _post_message(self, message, channel, code_block=True):

        url = SLACK_BASE_URL + 'chat.postMessage'

        body = {}
        body['channel'] = channel
        body['token'] = self.bot_token
        body['as_user'] = True

        if message:
            if len(message) <= SLACK_BOT_JSON_MESSAGE_LIMIT:
                body['text'] = '```{}```'.format(message) if code_block else message
                requests.post(url, data=body, timeout=SLACK_BOT_DEFAULT_TIMEOUT)
                return

            last_newline = message[:SLACK_BOT_JSON_MESSAGE_LIMIT - 1].rfind('\n')
            to_send = message[:last_newline]
            body['text'] = '```{}```'.format(to_send) if code_block else to_send
            requests.post(url, data=body, timeout=SLACK_BOT_DEFAULT_TIMEOUT)
            self._post_message(message[last_newline + 1:], channel, code_block=code_block)

    def _parse_action_parameters(self, actual_parameters: list, expected_parameters: dict, target: dict) -> Result:
        """ Verify the action parameters match the expected parameters and add them to the target. """
        if not actual_parameters and expected_parameters:
            for parameter_info in expected_parameters.values():
                if parameter_info.get('required', False):
                    return FailureResult('Specified action requires parameters, none given')

        if not actual_parameters:
            return SuccessResult(target)

        parsed_parameters = {}
        for parameter in actual_parameters:
            split_parameter = parameter.split(':', 1)
            if len(split_parameter) < 2:
                return FailureResult('Action parameters not formatted correctly')
            parameter_name = split_parameter[0]
            if parameter_name not in expected_parameters:
                return FailureResult(f'Invalid parameter: {parameter_name}')
            parsed_parameters[parameter_name] = split_parameter[1]

        target['parameters'] = [parsed_parameters]

        # Make sure all required parameters are present
        for key, value in expected_parameters.items():
            if value.get('required', False):
                for params in target['parameters']:
                    if key not in params:
                        return FailureResult('Missing required parameter: {key}')

        return SuccessResult(target)

    def _from_on_poll(self):
        """
        On poll method helps to establish the web socket connection with slack bot app on you slack
        using the slack-bolt sdk.
        """
        app = slack_app(token=self.bot_token)

        @app.event('app_mention')
        def mention_handler(body, say):
            """
            mention handler function uses a app_mention event decorator to response to the events whenever the bot
            is mentioned in the cat. It receives a json body which contains the data of the event. The command and
            channel name are parsed from the body and passed to command handler to further process the command.
            """
            logging.info('**app_mention handler hit')
            if body:
                user = body.get('event', {}).get('user')
                logging.info('**user that spawned bot command is %s', user)
                if not self._check_user_authorization(user):
                    say('`User {} is not authorized to use this bot`'.format(user))
                    return

                out_text = body.get('event', {}).get('text')
                logging.info('**body exists, app_mention text: %s', out_text)

                if out_text and out_text.startswith(self.cmd_start):
                    channel = body.get('event', {}).get('channel', '#general')
                    if out_text.strip() == self.cmd_start:
                        # Print out the help message in case of an empty command
                        self._post_message(
                            self._create_parser(channel).format_help(),
                            body.get('event', {}).get('channel', '#general'),
                        )

                    command = out_text[len(self.cmd_start):].strip()

                    if command and channel:
                        command = self._sanitize(command)
                        try:
                            self._handle_command(command, channel)
                        except Exception as e:
                            logging.exception('Exception while running command: %s', command)
                            try:
                                self._post_message(
                                    'Could not run command:\n\n{0}\n\n{1}'.format(command, e),
                                    channel,
                                )
                            except Exception as e:
                                self._post_message(
                                    'Could not run command:\n\n{0}'.format(e), channel
                                )

        @app.event('message')
        def handle_message_events(body, logger):
            """
            Ignore handling any general messages. Messages with a mention will be handled by the mention handler.

            Without this no-op handler definition a warning log will get printed every time a message comes in.
            """
            return

        handler = SocketModeHandler(app, self.socket_token)
        handler.start()

    def _check_user_authorization(self, user):
        logging.info('**Checking authorization for user "%s"', user)
        permitted_users = self.permitted_users

        if not permitted_users:
            logging.info('**No permitted users specified. Falling back to allow all.')
            return True

        else:
            user_list = permitted_users.split(',')
            logging.info('**Permitted_users: %s', user_list)
            if user in user_list:
                logging.info('**User "%s" is permitted to use bot', user)
                return True
            else:
                logging.info('**User "%s" is not permitted to use bot', user)
                return False

    def _create_parser(self, channel):
        parser = argparse.ArgumentParser(exit_on_error=False,
                                         prog='@<bot_username>',
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        subparsers = parser.add_subparsers(title='commands')
        for slack_bot_command in AVAILABLE_COMMANDS:
            subparser = subparsers.add_parser(slack_bot_command.COMMAND_NAME,
                                              description=slack_bot_command.COMMAND_DESCRIPTION,
                                              argument_default=argparse.SUPPRESS,  # Avoid printing None if no default
                                              formatter_class=argparse.ArgumentDefaultsHelpFormatter)
            command_instance = slack_bot_command(self, channel)
            command_instance.configure_parser(subparser)
            subparser.set_defaults(func=command_instance.check_authorization_and_execute)

        return parser

    def _handle_command(self, command, channel):
        parser = self._create_parser(channel)

        argparse_output_io = StringIO()
        argparse_errors_io = StringIO()
        try:
            # argparse writes to stdout and stderr, so we need to capture them
            sys.stdout = argparse_output_io
            sys.stderr = argparse_errors_io
            args = parser.parse_args(shlex.split(command))
        except (Exception, SystemExit) as e:
            # argparse sometimes also raises SystemExit exceptions despite the false exit_on_error flag
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

            argparse_output = argparse_output_io.getvalue()
            argparse_errors = argparse_errors_io.getvalue()

            failed_parsing_prefix = 'Could not parse arguments:'
            if argparse_errors:
                self._post_message(f'{failed_parsing_prefix}\n\n{argparse_errors}', channel)
            elif argparse_output:
                self._post_message(f'{failed_parsing_prefix}\n\n{argparse_output}', channel)
            elif hasattr(e, 'message'):
                self._post_message(f'{failed_parsing_prefix}\n\n{e.message}', channel)
            else:
                logging.exception('No output found from failed argument parsing attempt.')
                self._post_message(f'{failed_parsing_prefix}\n\n{e}', channel)
            return
        finally:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

        result_message = args.func(args)
        self._post_message(result_message, channel)


def main():  # noqa
    logging.info('**Spawning slack_bot_standalone.py...')
    if not os.path.exists('./bot_config.py'):
        if len(sys.argv) != 3:
            logging.error('Please create a bot_config.py file, and place it in this directory')
            sys.exit(1)

        asset_id = sys.argv[1]
        state = _load_app_state(asset_id)
        app_version = state.get('app_version')
        bot_id = state.get('bot_id')
        ph_base_url = state.get('ph_base_url')
        bot_token = state.get(SLACK_BOT_JSON_BOT_TOKEN)
        socket_token = state.get(SLACK_BOT_JSON_SOCKET_TOKEN)
        soar_auth_token = state.get(SLACK_BOT_JSON_SOAR_AUTH_TOKEN)
        command_permissions = {permission: state.get(permission.value, False)
                               for permission in CommandPermission}
        permitted_users = state.get(SLACK_BOT_JSON_PERMITTED_USERS)
        log_level = state.get(SLACK_BOT_JSON_LOG_LEVEL)
        logging.getLogger().setLevel(log_level)

        try:
            if bot_token:
                bot_token = decrypt_state(asset_id, bot_token, 'bot')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        try:
            if socket_token:
                socket_token = decrypt_state(asset_id, socket_token, 'socket')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        try:
            if soar_auth_token:
                soar_auth_token = decrypt_state(asset_id, soar_auth_token, 'soar_auth')
        except Exception:
            logging.exception(SLACK_BOT_DECRYPTION_ERROR)
            sys.exit(1)

        sb = SlackBot(
            bot_token=bot_token,
            socket_token=socket_token,
            bot_id=bot_id,
            base_url=ph_base_url,
            auth_token=soar_auth_token,
            command_permissions=command_permissions,
            permitted_users=permitted_users,
            app_version=app_version,
        )
        sb._from_on_poll()
        sys.exit(0)

    import bot_config

    fail = False

    logging.getLogger().setLevel(logging.DEBUG)

    try:
        bt = bot_config.BOT_TOKEN
        if not isinstance(bt, str):
            logging.error('The BOT_TOKEN entry in the bot_config file appears to not be a string')
            fail = True
    except Exception:
        logging.exception('Could not find a BOT_TOKEN entry in bot_config file')
        fail = True

    try:
        sat = bot_config.SOCKET_TOKEN
        if not isinstance(sat, str):
            logging.error(
                'The SOCKET_TOKEN entry in the bot_config file appears to not be a string'
            )
            fail = True
    except Exception:
        logging.exception('Could not find a SOCKET_TOKEN entry in bot_config file')
        fail = True

    try:
        pu = bot_config.PHANTOM_URL
        if not isinstance(pu, str):
            logging.error('The PHANTOM_URL entry in the bot_config file appears to not be a string')
            fail = True
    except Exception:
        logging.exception('Could not find a PHANTOM_URL entry in bot_config file')
        fail = True

    try:
        vc = bot_config.VERIFY_CERT
        if not isinstance(vc, bool):
            logging.error('The VERIFY_CERT entry in the bot_config file appears to not be a boolean')
            fail = True
    except Exception:
        logging.exception('Could not find a VERIFY_CERT entry in bot_config file')
        fail = True

    try:
        pt = bot_config.PHANTOM_TOKEN
        has_token = True
        if not isinstance(pt, str):
            logging.error('The PHANTOM_TOKEN entry in the bot_config file appears to not be a string')
            fail = True
    except Exception:
        pt = ''
        has_token = False

    try:
        pn = bot_config.PHANTOM_USERNAME
        pp = bot_config.PHANTOM_PASSWORD

        auth = (pn, pp)
        has_basic = True

        if not isinstance(pn, str):
            logging.error('The PHANTOM_USERNAME entry in the bot_config file appears to not be a string')
            fail = True
        if not isinstance(pp, str):
            logging.error('The PHANTOM_PASSWORD entry in the bot_config file appears to not be a string')
            fail = True
    except Exception:
        auth = ()
        has_basic = False

    if not (has_token or has_basic):
        logging.error('Please specify a form of authorization. '
              'Either PHANTOM_TOKEN or PHANTOM_USERNAME and PHANTOM_PASSWORD need to be included in the bot_config file.')
        fail = True

    try:
        resp = requests.post('https://slack.com/api/auth.test', data={'token': bot_config.BOT_TOKEN}, timeout=SLACK_BOT_DEFAULT_TIMEOUT)
        resp_json = resp.json()
    except Exception:
        logging.exception('Could not connect to Slack REST endpoint for auth check')
        sys.exit(1)

    if not resp_json.get('ok', False):
        logging.error('Given BOT_TOKEN failed authentication with Slack')
        fail = True

    bot_id = resp_json.get('user_id')

    if not bot_id:
        logging.error('Could not get bot username from Slack')
        fail = True

    if fail:
        logging.error('Config file failed verification, exiting')
        sys.exit(1)

    sb = SlackBot(
        bot_token=bot_config.BOT_TOKEN,
        socket_token=bot_config.SOCKET_TOKEN,
        bot_id=bot_id,
        base_url=bot_config.PHANTOM_URL,
        verify=bot_config.VERIFY_CERT,
        auth_token=pt,
        auth_basic=auth)
    sb._from_on_poll()


if __name__ == '__main__':
    log_file_path = Path(tempfile.gettempdir()) / 'slack_bot.log'
    logging.basicConfig(filename=log_file_path,
                        filemode='a',
                        format='[%(process)d][%(asctime)s][%(levelname)s] %(message)s')

    try:
        main()
    except Exception:
        logging.exception('Encountered an unhandled exception!')
        raise
