import psutil
import pytest
import os
import sys

from pathlib import Path
from typing import Optional

from volttrontesting.utils import get_rand_vip, get_rand_ip_and_port
from integration_tests.platform_wrapper_with_web import PlatformWrapperWithWeb as PlatformWrapper

# the following assumes that the testconf.py is in the tests directory.
volttron_src_path = Path(__file__).resolve().parent.parent.joinpath("src")

assert volttron_src_path.exists()

print(sys.path)
if str(volttron_src_path) not in sys.path:
    print(f"Adding source path {volttron_src_path}")
    sys.path.insert(0, str(volttron_src_path))

PRINT_LOG_ON_SHUTDOWN = False
HAS_WEB = False  # is_web_available()

ci_skipif = pytest.mark.skipif(os.getenv('CI', None) == 'true', reason='SSL does not work in CI')
web_skipif = pytest.mark.skipif(not HAS_WEB, reason='Web libraries are not installed')


def print_log(volttron_home):
    if PRINT_LOG_ON_SHUTDOWN:
        if os.environ.get('PRINT_LOGS', PRINT_LOG_ON_SHUTDOWN):
            log_path = volttron_home + "/volttron.log"
            if os.path.exists(log_path):
                with open(volttron_home + "/volttron.log") as fin:
                    print(fin.read())
            else:
                print('NO LOG FILE AVAILABLE.')


def build_wrapper(vip_address: str, should_start: bool = True, messagebus: str = 'zmq',
                  remote_platform_ca: Optional[str] = None,
                  instance_name: Optional[str] = None, secure_agent_users: bool = False, **kwargs):
    wrapper = PlatformWrapper(ssl_auth=kwargs.pop('ssl_auth', False),
                              messagebus=messagebus,
                              instance_name=instance_name,
                              secure_agent_users=secure_agent_users,
                              remote_platform_ca=remote_platform_ca)
    if should_start:
        wrapper.startup_platform(vip_address=vip_address, **kwargs)
    return wrapper


def cleanup_wrapper(wrapper):
    print('Shutting down instance: {0}, MESSAGE BUS: {1}'.format(wrapper.volttron_home, wrapper.messagebus))
    # if wrapper.is_running():
    #     wrapper.remove_all_agents()
    # Shutdown handles case where the platform hasn't started.
    wrapper.shutdown_platform()
    if wrapper.p_process is not None:
        if psutil.pid_exists(wrapper.p_process.pid):
            proc = psutil.Process(wrapper.p_process.pid)
            proc.terminate()
    if not wrapper.debug_mode:
        assert not Path(wrapper.volttron_home).parent.exists(), \
            f"{str(Path(wrapper.volttron_home).parent)} wasn't cleaned!"


def cleanup_wrappers(platforms):
    for p in platforms:
        cleanup_wrapper(p)


# Generic fixtures. Ideally we want to use the below instead of
# Use this fixture when you want a single instance of volttron platform for
# test
@pytest.fixture(scope="module",
                params=[
                    dict(messagebus='zmq', ssl_auth=False),
                ])
def volttron_instance(request, **kwargs):
    """Fixture that returns a single instance of volttron platform for volttrontesting

    @param request: pytest request object
    @return: volttron platform instance
    """
    address = kwargs.pop("vip_address", get_rand_vip())
    protocol = 'https' if kwargs.pop('ssl_auth', False) else 'http'
    bind_web_address = kwargs.pop("bind_web_address", f'{protocol}://{get_rand_ip_and_port()}')
    wrapper = build_wrapper(address,
                            bind_web_address=bind_web_address,
                            messagebus=request.param['messagebus'],
                            ssl_auth=request.param['ssl_auth'],
                            **kwargs)
    wrapper_pid = wrapper.p_process.pid

    try:
        yield wrapper
    except Exception as ex:
        print(ex.args)
    finally:
        cleanup_wrapper(wrapper)
        if not wrapper.debug_mode:
            assert not Path(wrapper.volttron_home).exists()
        # Final way to kill off the platform wrapper for the tests.
        if psutil.pid_exists(wrapper_pid):
            psutil.Process(wrapper_pid).kill()


# Use this fixture to get more than 1 volttron instance for test.
# Usage example:
# def test_function_that_uses_n_instances(request, get_volttron_instances):
#     instances = get_volttron_instances(3)
#
# TODO allow rmq to be added to the multi platform request.
@pytest.fixture(scope="module",
                params=[
                    dict(messagebus='zmq', ssl_auth=False)
                ])
def get_volttron_instances(request):
    """ Fixture to get more than 1 volttron instance for test
    Use this fixture to get more than 1 volttron instance for test. This
    returns a function object that should be called with number of instances
    as parameter to get a list of volttron instnaces. The fixture also
    takes care of shutting down all the instances at the end

    Example Usage:

    def test_function_that_uses_n_instances(get_volttron_instances):
        instance1, instance2, instance3 = get_volttron_instances(3)

    @param request: pytest request object
    @return: function that can used to get any number of
        volttron instances for volttrontesting.
    """
    instances = []

    def get_n_volttron_instances(n, should_start=True, **kwargs):
        nonlocal instances
        get_n_volttron_instances.count = n
        instances = []
        for i in range(0, n):
            address = kwargs.pop("vip_address", get_rand_vip())
            bind_web_address = kwargs.pop('bind_web_address', f'http://{get_rand_ip_and_port()}')

            wrapper = build_wrapper(address,
                                    bind_web_address=bind_web_address,
                                    should_start=should_start,
                                    messagebus=request.param['messagebus'],
                                    ssl_auth=request.param['ssl_auth'],
                                    **kwargs)
            instances.append(wrapper)
        if should_start:
            for w in instances:
                assert w.is_running()
        # instances = instances if n > 1 else instances[0]
        # setattr(get_n_volttron_instances, 'instances', instances)
        get_n_volttron_instances.instances = instances if n > 1 else instances[0]
        return instances if n > 1 else instances[0]

    def cleanup():
        nonlocal instances
        print(f"My instances: {get_n_volttron_instances.count}")
        if isinstance(get_n_volttron_instances.instances, PlatformWrapper):
            print('Shutting down instance: {}'.format(
                get_n_volttron_instances.instances))
            cleanup_wrapper(get_n_volttron_instances.instances)
            return

        for i in range(0, get_n_volttron_instances.count):
            print('Shutting down instance: {}'.format(
                get_n_volttron_instances.instances[i].volttron_home))
            cleanup_wrapper(get_n_volttron_instances.instances[i])

    try:
        yield get_n_volttron_instances
    finally:
        cleanup()
