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

import gevent
import grequests
import pytest
import os
import time

from configparser import ConfigParser
from mock import MagicMock

from volttron.client.known_identities import CONTROL

from volttrontesting.platformwrapper import with_os_environ
from volttrontesting.utils import get_rand_http_address, get_rand_tcp_address

from platform_wrapper_with_web import PlatformWrapperWithWeb


def test_will_update_environ():
    to_update = dict(farthing="50")
    with with_os_environ(to_update):
        assert os.environ.get("farthing") == "50"

    assert "farthing" not in os.environ


@pytest.mark.parametrize("messagebus, ssl_auth", [
    ('zmq', False),
    # ('zmq, True)
    # , ('rmq', True)
])
def test_can_create(messagebus, ssl_auth):
    p = PlatformWrapperWithWeb(messagebus=messagebus, ssl_auth=ssl_auth)
    try:
        assert not p.is_running()
        assert p.volttron_home.startswith("/tmp/tmp")
        http_address = get_rand_http_address()
        p.startup_platform(vip_address=get_rand_tcp_address(), bind_web_address=http_address)
        assert p.is_running()
        assert p.dynamic_agent.vip.ping("").get(timeout=2)
        result = grequests.get(http_address, verify=False).send()
        assert result
        response = result.response
        assert response.ok
    finally:
        if p:
            p.shutdown_platform()

    assert not p.is_running()


def test_volttron_config_created(volttron_instance):
    config_file = os.path.join(volttron_instance.volttron_home, "config")
    assert os.path.isfile(config_file)
    parser = ConfigParser()
    # with open(config_file, 'rb') as cfg:
    parser.read(config_file)
    assert volttron_instance.instance_name == parser.get('volttron', 'instance-name')
    assert volttron_instance.vip_address == parser.get('volttron', 'vip-address')
    assert volttron_instance.messagebus == parser.get('volttron', 'message-bus')


def test_can_restart_platform_without_addresses_changing(get_volttron_instances):
    inst_forward, inst_target = get_volttron_instances(2)

    original_vip = inst_forward.vip_address
    assert inst_forward.is_running()
    inst_forward.stop_platform()
    assert not inst_forward.is_running()
    gevent.sleep(5)
    inst_forward.restart_platform()
    assert inst_forward.is_running()
    assert original_vip == inst_forward.vip_address


def test_can_restart_platform(volttron_instance):
    orig_vip = volttron_instance.vip_address
    orig_vhome = volttron_instance.volttron_home
    orig_bus = volttron_instance.messagebus
    orig_bind = volttron_instance.bind_web_address
    orig_proc = volttron_instance.p_process.pid

    assert volttron_instance.is_running()
    volttron_instance.stop_platform()

    assert not volttron_instance.is_running()
    volttron_instance.restart_platform()
    assert volttron_instance.is_running()
    assert orig_vip == volttron_instance.vip_address
    assert orig_vhome == volttron_instance.volttron_home
    assert orig_bus == volttron_instance.messagebus
    assert orig_bind == volttron_instance.bind_web_address
    # Expecation that we won't have the same pid after we restart the platform.
    assert orig_proc != volttron_instance.p_process.pid
    assert len(volttron_instance.dynamic_agent.vip.peerlist().get()) > 0


@pytest.mark.skip(reason="To test actions on github")
def test_can_install_listener(volttron_instance: PlatformWrapperWithWeb):
    vi = volttron_instance
    assert vi is not None
    assert vi.is_running()

    # agent identity should be
    auuid = vi.install_agent(agent_dir="volttron-listener", start=False)
    assert auuid is not None
    time.sleep(1)
    started = vi.start_agent(auuid)

    assert started
    assert vi.is_agent_running(auuid)
    listening = vi.build_agent()
    listening.callback = MagicMock(name="callback")
    listening.callback.reset_mock()

    assert listening.core.identity
    agent_identity = listening.vip.rpc.call(CONTROL, 'agent_vip_identity', auuid).get(timeout=10)
    listening.vip.pubsub.subscribe(peer='pubsub',
                                   prefix='heartbeat/{}'.format(agent_identity),
                                   callback=listening.callback)

    # default heartbeat for core listener is 5 seconds.
    # sleep for 10 just in case we miss one.
    gevent.sleep(10)

    assert listening.callback.called
    call_args = listening.callback.call_args[0]
    # peer, sender, bus, topic, headers, message
    assert call_args[0] == 'pubsub'
    assert call_args[1] == agent_identity
    assert call_args[2] == ''
    assert call_args[3].startswith(f'heartbeat/{agent_identity}')
    assert 'max_compatible_version' in call_args[4]
    assert 'min_compatible_version' in call_args[4]
    assert 'TimeStamp' in call_args[4]
    assert 'GOOD' in call_args[5]

    stopped = vi.stop_agent(auuid)
    print('STOPPED: ', stopped)
    removed = vi.remove_agent(auuid)
    print('REMOVED: ', removed)
    listening.core.stop()


@pytest.mark.skip(reason="To test actions on github")
def test_reinstall_agent(volttron_instance):
    vi = volttron_instance
    assert vi is not None
    assert vi.is_running()

    auuid = vi.install_agent(agent_dir="volttron-listener", start=True, vip_identity="test_listener")
    assert volttron_instance.is_agent_running(auuid)

    newuuid = vi.install_agent(agent_dir="volttron-listener", start=True, force=True,
                               vip_identity="test_listener")
    assert vi.is_agent_running(newuuid)
    assert auuid != newuuid and auuid is not None
    vi.remove_agent(newuuid)


def test_can_stop_vip_heartbeat(volttron_instance):
    clear_messages()
    vi = volttron_instance
    assert vi is not None
    assert vi.is_running()

    agent = vi.build_agent(heartbeat_autostart=True,
                           heartbeat_period=1,
                           identity='Agent')
    agent.vip.pubsub.subscribe(peer='pubsub', prefix='heartbeat/Agent',
                               callback=onmessage)

    # Make sure heartbeat is recieved
    time_start = time.time()
    print('Awaiting heartbeat response.')
    while not messages_contains_prefix(
            'heartbeat/Agent') and time.time() < time_start + 10:
        gevent.sleep(0.2)

    assert messages_contains_prefix('heartbeat/Agent')

    # Make sure heartbeat is stopped

    agent.vip.heartbeat.stop()
    clear_messages()
    time_start = time.time()
    while not messages_contains_prefix(
            'heartbeat/Agent') and time.time() < time_start + 10:
        gevent.sleep(0.2)

    assert not messages_contains_prefix('heartbeat/Agent')


def test_get_peerlist(volttron_instance):
    vi = volttron_instance
    agent = vi.build_agent()
    assert agent.core.identity
    resp = agent.vip.peerlist().get(timeout=5)
    assert isinstance(resp, list)
    assert len(resp) > 1


@pytest.mark.skip(reason="To test actions on github")
def test_can_remove_agent(volttron_instance):
    """ Confirms that 'volttron-ctl remove' removes agent as expected. """
    assert volttron_instance is not None
    assert volttron_instance.is_running()

    # Install ListenerAgent as the agent to be removed.
    agent_uuid = volttron_instance.install_agent(
        agent_dir='volttron-listener', start=False)
    assert agent_uuid is not None
    started = volttron_instance.start_agent(agent_uuid)
    assert started is not None
    pid = volttron_instance.agent_pid(agent_uuid)
    assert pid is not None and pid > 0

    # Now attempt removal
    volttron_instance.remove_agent(agent_uuid)

    # Confirm that it has been removed.
    pid = volttron_instance.agent_pid(agent_uuid)
    assert pid is None


messages = {}


def onmessage(peer, sender, bus, topic, headers, message):
    messages[topic] = {'headers': headers, 'message': message}


def clear_messages():
    global messages
    messages = {}


def messages_contains_prefix(prefix):
    global messages
    return any([x.startswith(prefix) for x in list(messages.keys())])


def test_can_publish(volttron_instance):
    global messages
    clear_messages()
    vi = volttron_instance
    agent = vi.build_agent()
    #    gevent.sleep(0)
    agent.vip.pubsub.subscribe(peer='pubsub', prefix='test/world',
                               callback=onmessage).get(timeout=5)

    agent_publisher = vi.build_agent()
    #    gevent.sleep(0)
    agent_publisher.vip.pubsub.publish(peer='pubsub', topic='test/world',
                                       message='got data')
    # sleep so that the message bus can actually do some work before we
    # eveluate the global messages.
    gevent.sleep(0.1)
    assert messages['test/world']['message'] == 'got data'


@pytest.mark.skip(reason="To test actions on github")
def test_can_install_multiple_listeners(volttron_instance):
    assert volttron_instance.is_running()
    volttron_instance.remove_all_agents()
    uuids = []
    num_listeners = 3

    try:
        for x in range(num_listeners):
            identity = "listener_" + str(x)
            auuid = volttron_instance.install_agent(
                agent_dir="volttron-listener",
                config_file={
                    "agentid": identity,
                    "message": "So Happpy"},
                vip_identity=identity
            )
            assert auuid
            uuids.append(auuid)
            time.sleep(4)

        for u in uuids:
            assert volttron_instance.is_agent_running(u)

        agent_list = volttron_instance.dynamic_agent.vip.rpc(CONTROL, 'list_agents').get(timeout=5)
        print('Agent List: {}'.format(agent_list))
        assert len(agent_list) == num_listeners
    finally:
        for x in uuids:
            try:
                volttron_instance.remove_agent(x)
            except:
                print('COULDN"T REMOVE AGENT')
