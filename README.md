VOLTTRON™ is an open source platform for distributed sensing and control. The platform provides services for collecting and storing data from buildings and devices and provides an environment for developing applications which interact with that data.

[![Run Pytests](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-test.yml/badge.svg)](https://github.com/eclipse-volttron/volttron-lib-web/actions/workflows/run-test.yml)
[![pypi version](https://img.shields.io/pypi/v/volttron.svg)](https://pypi.org/project/volttron-core/)

## Installation with Web

```bash
> pip install volttron-lib-web
```

Configurations for services, including this web service, reside in a service_config.yml file in the VOLTTRON_HOME
directory (by default ~/.volttron/service_config.yml). If this file does not already exist, create it and include the
following:

```yaml
volttron.services.web:
  enabled: true
  kwargs:
    bind_web_address: http://127.0.0.156:5467
    web_secret_key: some_string # If not using SSL.
    web_ssl_cert: /path/to/certificate # Path to the SSL certificate to be used by the web service. 
    web_ssl_key: /path/to/key # Path to the SSL secret key file used by web service.


```
If using SSL, web_ssl_certificate and web_ssl_key are required. If not using SSL, provide a web_secret_key instead. 
### Quick Start

 1. Start the platform
    ```bash
    > volttron -vv -l volttron.log &>/dev/null &
    ```

 2. Install listener agent
    ```bash
    > vctl install volttron-listener
    ```

 3. View status of platform
    ```bash
    > vctl status
    ```

 4. Shutdown the platform
    ```bash
    > vctl shutdown --platform
    ```

Full VOLTTRON documentation available at [VOLTTRON Readthedocs](https://volttron.readthedocs.io)

## Contributing to VOLTTRON

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

## Development of VOLTTRON

### Environment

VOLTTRON uses [Poetry](https://python-poetry.org/), a dependency management and packaging tool for Python. If you don't have Poetry installed on your machine, follow [these steps](https://python-poetry.org/docs/#installation) to install it on your machine.

To check if Poetry is installed, run `poetry --version`. If you receive the error 'command not found: poetry', add the following line to your '~/.bashrc' script: ```export PATH=$PATH:$HOME/.poetry/bin```.

#### Recommended configuration for poetry

By default, poetry creates a virtual environment in {cache-dir}/virtualenvs. To configure 'poetry' to create the virtualenv inside this project's root directory, run the following command:

[```poetry config virtualenvs.in-project true```](https://python-poetry.org/docs/configuration)

### Setup

 1. Clone the repository
    ```bash
    git clone https://github.com/VOLTTRON/volttron-core -b develop
    ```

 1. cd into volttron-core directory
    ```bash
    cd volttron-core
    ```

 1. Install volttron into the current directory
    ```bash
    poetry install
    ```

 1. Run tests
    ```bash
    poetry run pytest
    ```

 1. Activate environment (removes the need for add poetry run to all commands)
    ```bash
    poetry shell
    ```

 1. Run volttron
    ```bash
    volttron -vv -l volttron.log &>/dev/null &
    ```

### Using modules to run VOLTTRON

In order to run VOLTTRON from within an ide the recommended way is to run the platform using the modules

 ```bash
 > poetry shell
 > python -m volttron.server -vv -l volttron.log &
 > python -m volttron.commands.control -vv status
```

Please see the [contributing.md](CONTRIBUTING.md) document before contributing to this repository.

Happy Editing!
