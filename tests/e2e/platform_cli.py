"""Drive a real VOLTTRON platform, with the web service enabled, through its command-line tools.

Adapted from ``drivers/interfaces/pymodbus/tests/platform_cli.py``. The platform runs in a temporary VOLTTRON_HOME
using the Python environment running the tests. Agents are installed with ``vctl``. This avoids
``volttrontesting.PlatformWrapper``, which does not yet support the modular platform's credential-based auth.
"""
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

# Keep poetry (which the platform uses to record installed agents) in the environment running the tests.
POETRY_LOCAL_CONFIG = "[virtualenvs]\ncreate = false\n\n[keyring]\nenabled = false\n"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def platform_config(instance_name: str, bind_address: str, secret_key: str, rpc_allow_list: list[str]) -> str:
    allow = ''.join(f'\n    {line}' for line in rpc_allow_list)
    return (
        '[volttron]\n'
        f'instance-name = {instance_name}\n'
        'agent-isolation-mode = False\n'
        'messagebus = zmq\n'
        'auth-enabled = True\n'
        'server-messagebus-id = vip.server\n'
        'agent-monitor-frequency = 600\n'
        '\n'
        '[web]\n'
        f'bind-web-address = {bind_address}\n'
        f'web-secret-key = {secret_key}\n'
        f'rpc-allow-list ={allow}\n'
    )


def poetry_project_for_current_environment() -> str:
    """A pyproject.toml pinning every installed distribution, with editable ones as develop path dependencies.

    On first start the platform builds this file itself, but it adds the editable packages *before* pinning the
    rest, and resolving their dependencies at that point upgrades packages such as volttron-core to the newest
    release on PyPI, changing the environment the tests run in. Providing the file up front means the platform only
    locks it and installs nothing.
    """
    from importlib import metadata
    pins, paths = [], []
    for dist in metadata.distributions():
        name = dist.metadata['Name']
        if not name or name.lower() == 'volttron':
            continue
        direct_url = dist.read_text('direct_url.json')
        info = json.loads(direct_url) if direct_url else {}
        if info.get('dir_info', {}).get('editable'):
            paths.append(f'"{name}" = {{path = "{info["url"].removeprefix("file://")}", develop = true}}')
        else:
            pins.append(f'"{name}" = "{dist.version}"')      # quoted: names may contain dots (backports.tarfile)
    v = sys.version_info
    return '\n'.join([
        '[tool.poetry]', 'name = "volttron"', 'version = "0.1.0"', 'description = ""',
        'authors = ["volttron <volttron@pnnl.gov>"]', 'package-mode = false', '',
        '[tool.poetry.dependencies]', f'python = "~{v.major}.{v.minor}.{v.micro}"',
        *sorted(paths), *sorted(pins), '',
        '[[tool.poetry.source]]', 'name = "test-pypi"', 'url = "https://test.pypi.org/simple/"',
        'priority = "supplemental"', '',
        '[build-system]', 'requires = ["poetry-core>=2.0.0,<3.0.0"]', 'build-backend = "poetry.core.masonry.api"', '',
    ])


class PlatformError(RuntimeError):
    pass


class PlatformCLI:
    def __init__(self, home: Path, instance_name: str = 'web-e2e', rpc_allow_list: list[str] = ()):
        self.home = Path(home)
        self.instance_name = instance_name
        self.port = free_port()
        self.bind_address = f'http://127.0.0.1:{self.port}'
        self.secret_key = secrets.token_hex(32)
        self.rpc_allow_list = list(rpc_allow_list)
        self.log = self.home.parent / 'volttron.log'
        self.bin = Path(sys.executable).parent
        venv = self.bin.parent
        self.env = {**os.environ, 'VOLTTRON_HOME': str(self.home), 'VIRTUAL_ENV': str(venv),
                    'PATH': f"{self.bin}:{os.environ.get('PATH', '')}",
                    'PYTHON_KEYRING_BACKEND': 'keyring.backends.null.Keyring'}
        self.process: subprocess.Popen | None = None

    # Distributions that provide a message bus, and with it the CredentialsStore the auth service needs. A venv with
    # volttron-core but none of these (CI installs only the web service's own dependencies) cannot start a platform.
    MESSAGE_BUS_DISTRIBUTIONS = ('volttron-lib-zmq',)

    @classmethod
    def available(cls) -> bool:
        from importlib import metadata
        bin = Path(sys.executable).parent
        if not all((bin / exe).exists() for exe in ('volttron', 'vctl')):
            return False
        for name in cls.MESSAGE_BUS_DISTRIBUTIONS:
            try:
                metadata.distribution(name)
                return True
            except metadata.PackageNotFoundError:
                continue
        return False

    # ------------------------------------------------------------------ lifecycle

    def start(self, timeout: float = 480.0):
        """Start the platform and wait until vctl can talk to it and the web server answers."""
        self.home.mkdir(parents=True, exist_ok=True)
        (self.home / 'config').write_text(platform_config(self.instance_name, self.bind_address, self.secret_key,
                                                          self.rpc_allow_list))
        (self.home / 'poetry.toml').write_text(POETRY_LOCAL_CONFIG)
        (self.home / 'pyproject.toml').write_text(poetry_project_for_current_environment())
        self.stdout = self.home.parent / 'volttron.stdout'
        with open(self.stdout, 'w') as out:
            self.process = subprocess.Popen([str(self.bin / 'volttron'), '-vv', '-l', str(self.log)], env=self.env,
                                            cwd=str(self.home.parent), stdout=out, stderr=subprocess.STDOUT)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise PlatformError(f'platform exited with {self.process.returncode}:\n{self.log_tail()}')
            if self._run(['vctl', 'status'], check=False, timeout=30).returncode == 0 and self._web_up():
                return
            time.sleep(3)
        raise PlatformError(f'platform did not become ready within {timeout}s:\n{self.log_tail()}')

    def _web_up(self) -> bool:
        try:
            with socket.create_connection(('127.0.0.1', self.port), timeout=2):
                return True
        except OSError:
            return False

    def shutdown(self):
        if self.process is None:
            return
        self._run(['vctl', 'shutdown', '--platform'], check=False, timeout=60)
        try:
            self.process.wait(30)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None

    def log_tail(self, lines: int = 40) -> str:
        parts = []
        stdout = getattr(self, 'stdout', None)
        if stdout and stdout.exists() and stdout.read_text().strip():
            parts.append('--- stdout/stderr ---\n' + '\n'.join(stdout.read_text().splitlines()[-lines:]))
        parts.append('--- log ---\n' + ('\n'.join(self.log.read_text().splitlines()[-lines:]) if self.log.exists() else '(no log)'))
        return '\n'.join(parts)

    def log_size(self) -> int:
        return len(self.log.read_text()) if self.log.exists() else 0

    def log_since(self, since: int) -> str:
        return self.log.read_text()[since:] if self.log.exists() else ''

    def wait_for_log(self, pattern: str, timeout: float = 90.0, since: int = 0) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.log.exists():
                for line in reversed(self.log_since(since).splitlines()):
                    if re.search(pattern, line):
                        return line
            time.sleep(1)
        raise PlatformError(f'{pattern!r} did not appear in the log within {timeout}s:\n{self.log_tail()}')

    # ------------------------------------------------------------------ commands

    def _run(self, args, check=True, timeout=120.0) -> subprocess.CompletedProcess:
        args = [str(self.bin / args[0]), *map(str, args[1:])]
        result = subprocess.run(args, env=self.env, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            raise PlatformError(f"{' '.join(args)} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}")
        return result

    def vctl(self, *args, timeout=180.0) -> str:
        return self._run(['vctl', *args], timeout=timeout).stdout

    def python(self, code: str, timeout=60.0) -> str:
        """Run a snippet with the platform's environment (VOLTTRON_HOME set)."""
        return self._run(['python', '-c', code], timeout=timeout).stdout

    def add_web_user(self, username: str, password: str, groups=('admin', 'vui')):
        self.python('from volttron.services.web.user_manager import add_web_user; '
                    f'add_web_user({username!r}, {password!r}, {list(groups)!r}, overwrite=True)')

    def install_agent(self, source: str, vip_identity: str, tag: str, timeout=400.0):
        """Install (editable when source is a directory) and start an agent, waiting until it reports running."""
        self.vctl('install', source, '--vip-identity', vip_identity, '--tag', tag, '--start', timeout=timeout)
        self.wait_for_running(vip_identity)

    def wait_for_running(self, vip_identity: str, timeout: float = 60.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if re.search(rf'\s{re.escape(vip_identity)}\s.*running', self.vctl('status')):
                return
            time.sleep(2)
        raise PlatformError(f'{vip_identity} did not start:\n{self.vctl("status")}\n{self.log_tail()}')

    def store_config(self, identity: str, name: str, path: Path, csv: bool = False):
        self.vctl('config', 'store', identity, name, str(path), *(['--csv'] if csv else []))
