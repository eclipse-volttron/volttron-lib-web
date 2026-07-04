# -*- coding: utf-8 -*- {{{
# ===----------------------------------------------------------------------===
#
#                 Installable Component of Eclipse VOLTTRON
#
# ===----------------------------------------------------------------------===
#
# Copyright 2022 Battelle Memorial Institute
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
Utility functions for managing VOLTTRON web users.

This module provides standalone functions for creating and managing web users,
independent of the AdminEndpoints web service. Can be used by CLI tools or
other utilities that need to manage web users without running the full web service.
"""

import json
import os
import shutil
import tempfile

from volttron.utils.context import ClientContext
from volttron.utils import jsonapi

try:
    from passlib.hash import argon2
except ImportError:
    raise ImportError("Missing passlib library required for web user management")


def _get_web_users_path():
    """Get the path to the web-users.json file."""
    return os.path.join(ClientContext.get_volttron_home(), 'web-users.json')


def _load_web_users_json():
    """
    Load web users from JSON file.

    :return: Dictionary of users, or empty dict if file doesn't exist
    """
    path = _get_web_users_path()
    if not os.path.exists(path):
        return {}

    try:
        with open(path, 'r') as f:
            return jsonapi.load(f)
    except (IOError, json.JSONDecodeError):
        return {}


def _write_web_users_json(users):
    """
    Write web users to JSON file atomically.

    Uses temp file + move pattern to ensure atomic writes and prevent corruption.

    :param users: Dictionary of users to write
    """
    path = _get_web_users_path()

    # Create temp file in same directory for atomic move
    dir_path = os.path.dirname(path)
    with tempfile.NamedTemporaryFile(
        mode='w',
        dir=dir_path,
        delete=False,
        suffix='.tmp'
    ) as tmp_file:
        jsonapi.dump(users, tmp_file, separators=(",", ":"))
        tmp_path = tmp_file.name

    try:
        # Atomic move
        shutil.move(tmp_path, path)
    except Exception:
        # Clean up temp file if move fails
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def load_web_users():
    """
    Load the web users dictionary from web-users.json.

    :return: Dictionary containing web users
    """
    return _load_web_users_json()


def add_web_user(username, unencrypted_pw, groups=None, overwrite=False):
    """
    Create or update a web user in the VOLTTRON web-users.json file.

    This is a standalone utility function that can be used by CLI tools or other
    utilities without needing to instantiate the full AdminEndpoints service.

    :param username: The username for the new user
    :param unencrypted_pw: The unencrypted password
    :param groups: List of groups to assign to the user (default: empty list)
    :param overwrite: If True, overwrite existing user; if False, raise error if user exists
    :raises ValueError: If user already exists and overwrite is False
    """
    if groups is None:
        groups = []

    users = _load_web_users_json()

    # Check if user already exists
    if username in users and not overwrite:
        raise ValueError(f"The user {username} is already present and overwrite not set to True")

    # Hash the password and store user
    hashed_pass = argon2.hash(unencrypted_pw)
    users[username] = dict(
        hashed_password=hashed_pass,
        groups=groups
    )

    _write_web_users_json(users)


def delete_web_user(username):
    """
    Delete a web user from the web-users.json file.

    :param username: The username to delete
    :raises ValueError: If user does not exist
    """
    users = _load_web_users_json()

    if username not in users:
        raise ValueError(f"The user {username} does not exist")

    del users[username]
    _write_web_users_json(users)


def update_web_user(username, unencrypted_pw=None, groups=None):
    """
    Update an existing web user's password and/or groups.

    :param username: The username to update
    :param unencrypted_pw: New password (optional, if not provided password is not changed)
    :param groups: New list of groups (optional, if not provided groups are not changed)
    :raises ValueError: If user does not exist
    """
    users = _load_web_users_json()

    if username not in users:
        raise ValueError(f"The user {username} does not exist")

    user_data = users[username]

    # Update password if provided
    if unencrypted_pw is not None:
        user_data['hashed_password'] = argon2.hash(unencrypted_pw)

    # Update groups if provided
    if groups is not None:
        user_data['groups'] = groups

    users[username] = user_data
    _write_web_users_json(users)


def get_web_user(username):
    """
    Retrieve a web user's data (without password hash).

    :param username: The username to retrieve
    :return: Dictionary with user data (excluding hashed_password)
    :raises ValueError: If user does not exist
    """
    userdict = load_web_users()

    if username not in userdict:
        raise ValueError(f"The user {username} does not exist")

    user_data = userdict[username].copy()
    # Don't return the hashed password
    user_data.pop('hashed_password', None)
    return user_data


def list_web_users():
    """
    List all web users (without password hashes).

    :return: Dictionary with all users (excluding hashed_password for each)
    """
    userdict = load_web_users()
    result = {}
    for username, user_data in userdict.items():
        user_copy = user_data.copy()
        user_copy.pop('hashed_password', None)
        result[username] = user_copy
    return result
