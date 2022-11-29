This package provides web services for the VOLTTRON™ platform.
This includes a RESTful API for interacting with the platform
and utility pages for administration and certificate management.
This library cannot be installed as a VOLTTRON agent is.
Rather, it must be installed as a python package.

[![Run Pytests](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-tests.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-tests.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron-lib-web.svg)](https://pypi.org/project/volttron-lib-web/)

## Requirements
* python >=3.8
* volttron >= 10.0

## Installation
This library can be installed using pip:

```bash
> pip install volttron-lib-web
```

Once the library is installed, VOLTTRON will not be able to start until the
web service is configured. Configurations for services, including this, reside
in a service_config.yml file in the VOLTTRON_HOME directory
(by default ~/.volttron/service_config.yml).
If this file does not already exist, create it. To configure the web service,
include the following:

```yaml
volttron.services.web:
  enabled: true
  kwargs:
    bind_web_address: http://192.168.0.101:8080
    web_secret_key: some_string # If not using SSL.
    web_ssl_cert: /path/to/certificate # Path to the SSL certificate to be used by the web service. 
    web_ssl_key: /path/to/key # Path to the SSL secret key file used by web service.
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

If using SSL, both web_ssl_certificate and web_ssl_key are required
and web_secret_key should not be included. If SSL is not desired,
provide a web_secret_key instead and remove the lines for the web_ssl_cert
and web_ssl_key. Any string can be used for the web_secret_key.

Full VOLTTRON documentation is available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)


## Use
Once the web service is installed, a web browser may be directed to the bind_web_address (http://192.168.1.101:8080
in the case shown in the configuration) to reach an index page. An admin page is also available at the /admin path
which can be used to create a username and password for authentication (http://192.168.1.101:8080/admin in the
configuration shown above). This will create a file called web-users.json in the VOLTTRON_HOME directory.

Additionally, the web service provides a RESTful API which can be used by other applications. Full documentation for
the API is available on 
[Readthedocs](https://volttron.readthedocs.io/en/main/platform-features/web-api/introduction.html).

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

Please see the following helpful guide about [developing modular VOLTTRON agents](https://github.com/eclipse-volttron/volttron-core/blob/develop/DEVELOPING_ON_MODULAR.md)

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
