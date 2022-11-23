import gevent

from volttron.client.known_identities import AUTH
from volttron.client.vip.agent import Agent

from volttrontesting.platformwrapper import with_os_environ


def test_get_credentials(volttron_instance):
    instance = volttron_instance
    auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
    len_auth_pending = len(auth_pending)
    with with_os_environ(instance.env):
        pending_agent = Agent(identity="PendingAgent")
        task = gevent.spawn(pending_agent.core.run)
        task.join(timeout=5)
        pending_agent.core.stop()

    auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
    print(f"Auth pending is: {auth_pending}")

    assert len(auth_pending) == len_auth_pending + 1


def test_accept_credential(volttron_instance):
    instance = volttron_instance
    auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
    len_auth_pending = len(auth_pending)
    with with_os_environ(instance.env):
        pending_agent = Agent(identity="PendingAgent1")
        task = gevent.spawn(pending_agent.core.run)
        task.join(timeout=5)
        pending_agent.core.stop()

        auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
        print(f"Auth pending is: {auth_pending}")
        assert len(auth_pending) == len_auth_pending + 1

        auth_approved = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_approved").get(timeout=10)
        len_auth_approved = len(auth_approved)
        assert len_auth_approved == 0

        print(f"agent uuid: {pending_agent.core.agent_uuid}")
        instance.dynamic_agent.vip.rpc.call(AUTH, "approve_authorization_failure", auth_pending[0]["user_id"]).wait(timeout=4)
        gevent.sleep(2)
        auth_approved = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_approved").get(timeout=10)

        assert len(auth_approved) == len_auth_approved + 1


def test_deny_credential(volttron_instance):
    instance = volttron_instance
    auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
    len_auth_pending = len(auth_pending)
    with with_os_environ(instance.env):
        pending_agent = Agent(identity="PendingAgent2")
        task = gevent.spawn(pending_agent.core.run)
        task.join(timeout=5)
        pending_agent.core.stop()

        auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
        print(f"Auth pending is: {auth_pending}")
        assert len(auth_pending) == len_auth_pending + 1

        auth_denied = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_denied").get(timeout=10)
        len_auth_denied = len(auth_denied)
        assert len_auth_denied == 0

        print(f"agent uuid: {pending_agent.core.agent_uuid}")
        instance.dynamic_agent.vip.rpc.call(AUTH, "deny_authorization_failure", auth_pending[0]["user_id"]).wait(timeout=4)
        gevent.sleep(2)
        auth_denied = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_denied").get(timeout=10)

        assert len(auth_denied) == len_auth_denied + 1


def test_delete_credential(volttron_instance):
    instance = volttron_instance
    auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
    print(f"Auth pending is: {auth_pending}")
    len_auth_pending = len(auth_pending)
    with with_os_environ(instance.env):
        pending_agent = Agent(identity="PendingAgent3")
        task = gevent.spawn(pending_agent.core.run)
        task.join(timeout=5)
        pending_agent.core.stop()

        auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)
        print(f"Auth pending is: {auth_pending}")
        assert len(auth_pending) == len_auth_pending + 1

        instance.dynamic_agent.vip.rpc.call(AUTH, "delete_authorization_failure", auth_pending[0]["user_id"]).wait(timeout=4)
        gevent.sleep(2)
        auth_pending = instance.dynamic_agent.vip.rpc.call(AUTH, "get_authorization_pending").get(timeout=10)

        assert len(auth_pending) == len_auth_pending
