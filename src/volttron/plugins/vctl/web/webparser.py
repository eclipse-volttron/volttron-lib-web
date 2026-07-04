# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2023 Battelle Memorial Institute
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# ===----------------------------------------------------------------------===
# }}}
"""
vctl web subcommand parser plugin. provide vctl web subcommand
"""

import sys

from volttron.utils.prompts import prompt_for_password, prompt_for_username
from volttron.types.factories import ControlParser
from volttron.client.decorators import vctl_subparser


# Suppress harmless gevent cleanup error on exit
# This occurs because control.py patches gevent globally but this module doesn't use RPC
# Set up exception hook at module import time
_original_excepthook = sys.excepthook

def _custom_excepthook(exc_type, exc_value, traceback):
    """Custom exception hook to suppress gevent cleanup errors."""
    # Ignore gevent cleanup errors
    if exc_type is RuntimeError and "greenlet is being finalized" in str(exc_value):
        return
    _original_excepthook(exc_type, exc_value, traceback)

sys.excepthook = _custom_excepthook

_stdout = sys.stdout
_stderr = sys.stderr


def create_admin_user(opts):
    """
    Create or update an admin user for the VOLTTRON web interface.

    Prompts the user for a username and password, then creates the admin user
    in the web-users.json file.

    :param opts: Command line options containing 'overwrite' flag
    """
    try:
        # Prompt for username
        username = prompt_for_username("Enter admin username")
        from volttron.services.web.user_manager import load_web_users
        # Prompt for password (with verification)
        password = prompt_for_password("Enter admin password", verify=True)

        # Import here to avoid circular dependency
        from volttron.services.web.user_manager import add_web_user

        # Add the user with admin and vui groups
        add_web_user(
            username=username,
            unencrypted_pw=password,
            groups=['admin', 'vui'],
            overwrite=opts.overwrite
        )

        _stdout.write(f"Successfully created admin user '{username}'\n")

    except ValueError as e:
        _stderr.write(f"ERROR: {str(e)}\n")
    except Exception as e:
        _stderr.write(f"ERROR: Failed to create admin user: {str(e)}\n")


@vctl_subparser
class WebVCtlParser(ControlParser):
    """
    vctl 'web' subcommand parser plugin.

    Provides commands for managing vui web commands
    """

    class Meta:
        name = "web"

    def configure(self, ctx):
        """
        Configure the 'web' subcommand and its subparsers.

        :param ctx: VctlParserContext for registering commands
        """
        # Top-level 'web' command
        web_cmds = ctx.register_command("web", help="commands to use volttron web library")

        web_subparsers = web_cmds.add_subparsers(title="subcommands", metavar="", dest="store_commands")

        # web create-admin
        create_admin = ctx.register_subcommand(web_subparsers, "create-admin",
                                               help="create or update admin user for volttron web")
        create_admin.add_argument("--overwrite", action="store_true", default=False,
                                help="overwrite existing admin user")
        create_admin.set_defaults(func=create_admin_user)
