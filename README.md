This package provides web services for the VOLTTRON™ platform.
This includes a RESTful API for interacting with the platform
and utility pages for administration and certificate management.
This library cannot be installed as a VOLTTRON agent is.
Rather, it must be installed as a python package.

[![Run Pytests](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-test.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-test.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron-lib-web/)

## Requirements
* python >=3.8
* volttron >= 10.0

## Installation with Web
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
    bind_web_address: http://127.0.0.156:5467
    web_secret_key: some_string # If not using SSL.
    web_ssl_cert: /path/to/certificate # Path to the SSL certificate to be used by the web service. 
    web_ssl_key: /path/to/key # Path to the SSL secret key file used by web service.
```

If using SSL, both web_ssl_certificate and web_ssl_key are required
and web_secret_key should not be included. If SSL is not desired,
provide a web_secret_key instead and remove the lines for the web_ssl_cert
and web_ssl_key.

Full VOLTTRON documentation is available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)

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