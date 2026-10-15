"""Fixtures for the live web-service tests.

A real platform is started in a temporary VOLTTRON_HOME with the web service enabled, one web user, the Platform
Driver with a fake device, and a listener agent. Set WEB_SKIP_E2E=1 to skip these tests.
"""
import json
import os
import time
from pathlib import Path

import pytest
import requests

from platform_cli import PlatformCLI

MODULAR = Path(__file__).resolve().parents[3]
PLATFORM_DRIVER_SOURCE = str(MODULAR / 'drivers' / 'platform-driver-agent')
FAKE_DRIVER_DIR = MODULAR / 'drivers' / 'interfaces' / 'fake'

PLATFORM_DRIVER = 'platform.driver'
LISTENER = 'listener'
CONTROL = 'platform.control'
DEVICE_TOPIC = 'fake-campus/fake-building/fake-device'
USERNAME, PASSWORD = 'admin', 'correct horse battery staple'

RPC_ALLOW_LIST = [
    f'{CONTROL}: peerlist, list_agents',
    f'{LISTENER}: *',
]


def _device_config(tmp_path_factory) -> Path:
    """The fake driver's sample device config, with duplicate remotes allowed.

    Workaround (2026-10-14): platform_driver.agent._get_or_create_remote passes the generic RemoteConfig to the
    interface's unique_remote_id, but the fake interface reads ``remote_id`` from its own FakeRemoteConfig, so
    configuring the device raises AttributeError and the device is never polled. With allow_duplicate_remotes the
    base implementation is used instead.
    """
    config = json.loads((FAKE_DRIVER_DIR / 'fake.config').read_text())
    config['allow_duplicate_remotes'] = True
    path = tmp_path_factory.mktemp('configs') / 'fake-device.json'
    path.write_text(json.dumps(config))
    return path


@pytest.fixture(scope='session')
def platform(tmp_path_factory):
    if os.environ.get('WEB_SKIP_E2E'):
        pytest.skip('WEB_SKIP_E2E is set')
    if not PlatformCLI.available():
        pytest.skip('volttron and vctl are not installed in this environment')
    cli = PlatformCLI(tmp_path_factory.mktemp('platform') / 'volttron_home', rpc_allow_list=RPC_ALLOW_LIST)
    cli.start()
    try:
        cli.add_web_user(USERNAME, PASSWORD)
        # platform.web is only granted control.* capabilities by libauth; the config write endpoints need these
        # (operators must grant them explicitly, this mirrors that step).
        cli.vctl('authz', 'add', 'agent', 'platform.web', '--rpc-capabilities',
                 'platform.config_store.set_config', 'platform.config_store.delete_config',
                 'platform.config_store.delete_store')
        cli.install_agent(PLATFORM_DRIVER_SOURCE, vip_identity=PLATFORM_DRIVER, tag='driver')
        cli.store_config(PLATFORM_DRIVER, 'registry_configs/fake.csv', FAKE_DRIVER_DIR / 'fake.csv', csv=True)
        cli.store_config(PLATFORM_DRIVER, f'devices/{DEVICE_TOPIC}', _device_config(tmp_path_factory))
        cli.install_agent('volttron-listener', vip_identity=LISTENER, tag='listener')
        yield cli
    finally:
        cli.shutdown()


@pytest.fixture(scope='session')
def base_url(platform):
    return platform.bind_address


@pytest.fixture(scope='session')
def tokens(base_url):
    r = requests.post(f'{base_url}/authenticate', json={'username': USERNAME, 'password': PASSWORD}, timeout=10)
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(scope='session')
def api(base_url, tokens):
    """A requests session carrying the access token, with the base URL prepended to relative paths."""
    s = requests.Session()
    s.headers['Authorization'] = f"Bearer {tokens['access_token']}"
    base = base_url

    class Api:
        def request(self, method, path, **kw):
            kw.setdefault('timeout', 30)
            return s.request(method, base + path, **kw)

        def __getattr__(self, name):
            if name in ('get', 'put', 'post', 'delete', 'head', 'options', 'patch'):
                return lambda path, **kw: self.request(name.upper(), path, **kw)
            raise AttributeError(name)

        url = base
        session = s
        access_token = tokens['access_token']

    return Api()


@pytest.fixture(scope='session')
def platform_name(platform):
    return platform.instance_name


@pytest.fixture(scope='session')
def P(platform_name):
    """Prefix for the local platform's VUI routes."""
    return f'/vui/platforms/{platform_name}'


def wait_until(predicate, timeout=30.0, interval=1.0, message='condition not met'):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    raise AssertionError(f'{message} within {timeout}s (last value: {last!r})')
