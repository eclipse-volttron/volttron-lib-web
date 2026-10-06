This package provides web services for the VOLTTRON™ platform.
This includes a RESTful API for interacting with the platform
and utility pages for administration and certificate management.
This library cannot be installed as a VOLTTRON agent is.
Rather, it must be installed as a python package.

![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)
![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)
[![Run Pytests](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron-lib-web.svg)](https://pypi.org/project/volttron-lib-web/)

# Requires

* python >= 3.10
* volttron >= 10.0
* jinja2-cli >= 0.7.0
* passlib >= 1.7.4
* PyJWT == 1.7.1
* treelib >= 1.6.1
* werkzeug >= 2.1.2
* ws4py = >= 0.5.1
* requests >= 2.28.1
* argon2-cffi >= 21.3.0

## Installation
This library can be installed using pip:

```bash
> pip install volttron-lib-web
```

Once the library is installed, VOLTTRON will not be able to start until the
web service is configured. The web service is configured in a `[web]` section of the VOLTTRON platform
configuration file in VOLTTRON_HOME (by default ~/.volttron/config). To configure the web service,
include the following:

```ini
[web]
bind-web-address = http://192.168.0.101:8080
web-secret-key = some_string  # If not using SSL.
web-ssl-cert = /path/to/certificate  # Path to the SSL certificate to be used by the web service.
web-ssl-key = /path/to/key  # Path to the SSL secret key file used by web service.
rpc-allow-list =
    platform.historian: query*
    my.app.*: *
web-root-dir = /var/lib/volttron/web-root  # Optional, see "Agent web files" below.
```

Additionally, in order to use many of the API endpoints, an instance name must be set in the VOLTTRON platform
configuration file in VOLTTRON_HOME (by default ~/.volttron/config).  If this file does not already exist, create it.
Ensure that it contains at least the following (where "my_instance_name" will be the name of this platform):

```ini
[volttron]
instance-name=my_instance_name
```

The bind_web_address will typically be the IP address of the host on which the web service is installed.
Setting the bind_web_address to 0.0.0.0 will bind to all interfaces on the machine. 127.0.0.1 or localhost
can be used if it is not desired for the web services to be reachable by other hosts. The port number
(after the colon) can be any port which is not bound to another service on the host mahcine.
80 or 8080 are common ports when not using SSL. 443 and 8443 are common ports to use when using SSL.

If using SSL, both web-ssl-cert and web-ssl-key are required
and web-secret-key should not be included. If SSL is not desired,
provide a web-secret-key instead and remove the lines for the web-ssl-cert
and web-ssl-key. Any string can be used for the web-secret-key.

### RPC allow-list

The `/vui/platforms/:platform/agents/:vip_identity/rpc/:method` endpoint forwards remote procedure calls to agents
using the web service's own platform identity. It is closed by default: unless `rpc-allow-list` is configured, every
request to it is refused with `403 Forbidden`. Each line of `rpc-allow-list` (continuation lines must be indented)
opens a set of methods on a set of agents:

```ini
rpc-allow-list =
    [platform-glob:] identity-glob: method-glob[, method-glob ...]
```

Patterns are shell-style globs (`*`, `?`, `[seq]`) matched case-sensitively against the whole name. A line with two
fields applies to every platform; a leading platform field restricts the entry to platforms whose instance name
matches it. For example:

```ini
rpc-allow-list =
    platform.historian: query*                    # query methods of the historian, on every platform
    my.app.*: *                                   # every method of agents whose identity starts with my.app.
    building2: some.agent: get_status, get_config # two methods, only when addressed through platform building2
```

To open every method of every installed agent, use `rpc-allow-list = *: *`.

Regardless of the allow-list, the proxy never forwards calls to the platform services `platform.auth`,
`platform.web`, `config.store` and `platform.driver`, nor to the agent lifecycle and installation methods of
`platform.control` (install, remove, start/stop platform, and similar). The dedicated `/agents` and `/devices`
endpoints of the API provide the supported management and device operations.

### Agent web files

An agent can publish static files (an HTML user interface, scripts, images) through the web service by calling
`register_path_route(regex)` on `platform.web`, where `regex` matches the request paths that should be served. The
agent does not choose the directory the files are served from. Every agent has exactly one allotted *web root*, and
only that directory can be registered:

- By default the web root is `$VOLTTRON_HOME/agents/<vip-identity>/data/web-root`. The agent must create it and
  place its files there; nothing else in its data directory is reachable.
- If `web-root-dir` is set in the `[web]` section, the web root is `<web-root-dir>/<vip-identity>` instead and the
  default location is no longer accepted. This keeps agent web files outside `VOLTTRON_HOME`, so they survive a
  reinstall of the agent. The configured directory must already exist, must not be the filesystem root, and must
  not be `VOLTTRON_HOME` or any directory containing it.

The agent can ask for its web root with the `get_web_root` RPC method of `platform.web`. The full request path is
appended to the web root when a file is served, so the directory layout must mirror the URL paths the regex
matches. Hidden files and directories (names beginning with a dot) and anything that is not a regular file are never
served, and every file is served with `X-Content-Type-Options: nosniff`.

Full VOLTTRON documentation is available at [VOLTTRON Readthedocs](https://eclipse-volttron.readthedocs.io/)


## Use
Once the web service is installed, a web browser may be directed to the bind_web_address (http://192.168.1.101:8080
in the case shown in the configuration) to reach an index page. An admin page is also available at the /admin path
which can be used to create a username and password for authentication (http://192.168.1.101:8080/admin in the
configuration shown above). This will create a file called web-users.json in the VOLTTRON_HOME directory.

Additionally, the web service provides a RESTful API which can be used by other applications. Full documentation for
the API is available on 
[Readthedocs](https://eclipse-volttron.readthedocs.io/en/latest/external-docs/volttron-lib-web/index.html).

Note that it is necessary for most API endpoints to have previously created a username and password for authentication
by visiting the /admin page or by manually copying or creating a web-users.json file. Authentication can then be
performed by making a POST request to the /authenticate endpoint to obtain an access token. The access token should then
be included in any subsequent requests to the API by passing the token as a BEARER token in an HTTP authorization
header. A simple example of using the API from a python script to retrieve a json object containing API routes to all
platforms known to this host is shown here:

```python
import requests
bind_web_address = 'http://192.168.1.101:8080'
tokens = requests.post(url=f'{bind_web_address}/authenticate',
                         json={"username": "my_user", "password": "my_password"})
access_token = tokens.json()['access_token']

platforms = requests.get(url=f'{bind_web_address}/vui/platforms',
                         headers={'Authorization': f'Bearer {access_token}'}
                         )
print(platforms.json())
```

## Development

Please see the following for contributing guidelines [contributing](https://github.com/eclipse-volttron/volttron-core/blob/develop/CONTRIBUTING.md).

Please see the following helpful guide about [developing modular VOLTTRON agents](https://eclipse-volttron.readthedocs.io/en/latest/developing-volttron/developing-agents/agent-development.html)

# Disclaimer Notice

This material was prepared as an account of work sponsored by an agency of the
United States Government.  Neither the United States Government nor the United
States Department of Energy, nor Battelle, nor any of their employees, nor any
jurisdiction or organization that has cooperated in the development of these
materials, makes any warranty, express or implied, or assumes any legal
liability or responsibility for the accuracy, completeness, or usefulness or any
information, apparatus, product, software, or process disclosed, or represents
that its use would not infringe privately owned rights.

Reference herein to any specific commercial product, process, or service by
trade name, trademark, manufacturer, or otherwise does not necessarily
constitute or imply its endorsement, recommendation, or favoring by the United
States Government or any agency thereof, or Battelle Memorial Institute. The
views and opinions of authors expressed herein do not necessarily state or
reflect those of the United States Government or any agency thereof.
