.. _Platforms-Agents-Configs-Endpoints:

==================================
Platforms Agents Configs Endpoints
==================================

Platforms Agents Configs endpoints expose functionality associated with agent configurations stored in the
VOLTTRON Configuration Store.

.. attention::
    All Platforms Configs endpoints require a JWT bearer token obtained through the
    ``POST /authenticate`` or ``PUT /authenticate`` endpoints.

--------------

GET /platforms/:platform/agents/:vip_identity/configs
=====================================================

Get routes to available configuration files for the specified agent.

Query parameters:

* ``metadata`` (default ``false``): when ``true`` the response also carries a ``configs`` object with the stored
  ``type`` (``json``, ``csv`` or ``raw``), the ``modified`` time (ISO 8601, ``null`` for entries that predate it), the
  ``etag`` and the ``size`` in bytes of every entry, beside the ``links``. With the ``-`` wildcard in place of the
  identity and ``metadata=true`` the response maps every identity that has a store to its number of entries.
  ``HEAD`` is accepted on this route and returns the headers only.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response
--------

* **With valid BEARER token on success:** ``200 OK``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "route_options": {
                    ":config_file_name": "/platforms/:platform/agents/:vip_identity/configs/:config_file_name",
                    "<config_file_name>": "/platforms/:platform/agents/:vip_identity/configs/:config_file_name",
                }
            }

* **With valid BEARER token on failure:** ``400 Bad Request``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

--------------------------------------------------------------------------------------------------

POST /platforms/:platform/agents/:vip_identity/configs/
========================================================

Save a new configuration file to the config store.

The file name should be passed in the query parameter file-name.

The file should match the content type and contents which the VOLTTRON configuration store expects.
The configuration store currently accepts only JSON, CSV, or RAW files. The content type header should match the type
of file being sent (``application/json``, ``text/csv``, or ``text/plain`` respectively). This endpoint
will return 409 Conflict if the configuration file already exists. In this case, the user should use
``PUT /platforms/:platform/agents/:vip_identity/configs/:file_name`` if modification of the existing file is truly
intended.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``
* Content Type: ``application/json``, ``text/csv``, or ``text/plain``
* Body: Contents of configuration file.

Response
--------

* **With valid BEARER token on success:** ``201 Created``
    - Location: /platforms/:platform/agents/:vip_identity/configs/:file_name
    - Content Type: ``application/json``, ``text/csv``, or ``text/plain``
    - Body: Contents of the configuration file.

* **With valid BEARER token on failure:** ``400 Bad Request`` or ``409 Conflict``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

* **With valid BEARER token but the web service lacks the platform capability for the config store write:**
  ``403 Forbidden``. The platform grants ``platform.web`` only control capabilities by default; an administrator
  must grant ``platform.config_store.set_config``, ``delete_config`` and ``delete_store`` (e.g. with
  ``vctl authz add agent platform.web --rpc-capabilities ...``) before configurations can be written.

-----------------------------------------------------------------------------------------

DELETE /platforms/:platform/agents/:vip_identity/configs/
==========================================================

Remove the configuration store for an agent. This endpoint will return ``409 Conflict`` if
the store for this agent is not empty. To remove all existing configurations for an agent from the config store
and delete the store, ``true`` must be passed to the ``all`` query parameter.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``
* Query Parameters:
    * ``all``: Boolean (default ``false``)

Response
--------

* **With valid BEARER token on success:** ``204 No Content``

* **With valid BEARER token on failure:** ``400 Bad Request`` or ``409 Conflict``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

* **With valid BEARER token but the web service lacks the platform capability for the config store write:**
  ``403 Forbidden``. The platform grants ``platform.web`` only control capabilities by default; an administrator
  must grant ``platform.config_store.set_config``, ``delete_config`` and ``delete_store`` (e.g. with
  ``vctl authz add agent platform.web --rpc-capabilities ...``) before configurations can be written.

------------------------------------------------------------------------------------------------

GET /platforms/:platform/agents/:vip_identity/configs/:config_name
==================================================================

Get a configuration file for the agent from the config store.

The configuration store can currently return JSON, CSV, or RAW files. If the Accept header is not set,
the configuration store will return JSON by default. If the client wishes to restrict the type of file received,
it should set the Accept header to the correct MIME type(s) (``application/json``, ``text/csv``, or ``text/plain``
respectively).

Every response carries the entry's metadata in headers: ``ETag``, a strong validator over the stored type and text;
``Config-Type``, the stored type (``json``, ``csv`` or ``raw``), which the ``Content-Type`` of a negotiated response
does not reveal; and ``Last-Modified``, when the store recorded a modification time (entries written before the
store kept one have none). Conditional requests are honoured: ``If-None-Match`` (a list of validators or ``*``, weak
prefixes ignored) and, when it is absent, ``If-Modified-Since`` answer ``304 Not Modified`` with the same headers and
no body. An entry without a recorded modification time never answers ``304`` to ``If-Modified-Since``.

``HEAD`` is accepted and returns the status and headers a ``GET`` would, without the body. A ``HEAD`` must not carry
a ``Content-Type`` header, since the web service parses a JSON body whenever one is declared.

Query parameters:

* ``metadata`` (default ``false``): when ``true`` the body is the metadata object instead of the contents:

  .. code-block:: javascript

        {
            "type": "csv",
            "modified": "2026-10-29T12:34:56.123456+00:00",
            "etag": "\"3f786850e387550fdab836ed7e6dc881\"",
            "size": 21
        }

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response
--------

* **With valid BEARER token on success:** ``200 OK``
    - Content Type: ``application/json``, ``text/csv``, or ``text/plain``
    - Body: Contents of the configuration file.
    - Headers: ``ETag``, ``Config-Type``, ``Last-Modified`` (when recorded)

* **With a matching condition:** ``304 Not Modified`` with the same headers and no body.

* **With valid BEARER token on failure:** ``400 Bad Request``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

-----------------------------------------------------------------------------------------

PUT /platforms/:platform/agents/:vip_identity/configs/:config_name
==================================================================

Overwrite a configuration file already in the config store.

The file should match the content type and contents which the VOLTTRON configuration store expects.
The configuration store currently accepts only JSON, CSV, or RAW files. The content type header should match the type
of file being sent (``application/json``, ``text/csv``, or ``text/plain`` respectively).

Query parameters (also accepted by ``POST``):

* ``trigger-callback`` (default ``true``): forwarded to the store; ``false`` stores the entry without running the
  agent's configuration callback.
* ``send-update`` (default ``true``): forwarded to the store; ``false`` stores the entry without telling the agent.
  A client applying several entries of one agent can turn it off for all but the last.

An ``If-Match`` header (a list of validators or ``*``) makes the write conditional on the entry's current ``ETag``:
on a mismatch, or when the entry does not exist, the response is ``412 Precondition Failed`` with the current
``etag`` (``null`` when absent) and nothing is written.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``
* Content Type: ``application/json``, ``text/csv``, or ``text/plain``
* Body: Contents of configuration file.

Response
--------

* **With valid BEARER token on success:** ``204 No Content``

* **With an If-Match that does not match:** ``412 Precondition Failed``

* **With valid BEARER token on failure:** ``400 Bad Request``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

* **With valid BEARER token but the web service lacks the platform capability for the config store write:**
  ``403 Forbidden``. The platform grants ``platform.web`` only control capabilities by default; an administrator
  must grant ``platform.config_store.set_config``, ``delete_config`` and ``delete_store`` (e.g. with
  ``vctl authz add agent platform.web --rpc-capabilities ...``) before configurations can be written.

-----------------------------------------------------------------------------------------

DELETE /platforms/:platform/agents/:vip_identity/configs/:config_name
=====================================================================

Remove an existing configuration file for the agent from the config store.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response
--------

* **With valid BEARER token on success:** ``204 No Content``

* **With valid BEARER token on failure:** ``400 Bad Request``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

* **With valid BEARER token but the web service lacks the platform capability for the config store write:**
  ``403 Forbidden``. The platform grants ``platform.web`` only control capabilities by default; an administrator
  must grant ``platform.config_store.set_config``, ``delete_config`` and ``delete_store`` (e.g. with
  ``vctl authz add agent platform.web --rpc-capabilities ...``) before configurations can be written.

.. toctree::
    :hidden:

    self
