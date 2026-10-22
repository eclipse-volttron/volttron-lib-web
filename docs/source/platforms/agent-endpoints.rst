.. _Platforms-Agents-Endpoints:

==========================
Platforms Agents Endpoints
==========================

Platforms Agents endpoints expose functionality associated with applications
running on a VOLTTRON platform.

Platforms Agents endpoints currently include:
    * :ref:`Configs <Platforms-Agents-Configs-Endpoints>`: Endpoints for managing the configuration store for agents
      on the platform.
    * :ref:`Enabled <Platforms-Agents-Enabled-Endpoints>`: Endpoints for enabling, disabling, and setting the start
      priority of agents on the platform.
    * :ref:`Running <Platforms-Agents-Running-Endpoints>`: Endpoints for starting and stopping agents on the platform.
    * :ref:`RPC <Platforms-Agents-Rpc-Endpoints>`: Endpoints allowing, discovery, inspection, and calling of remote
      procedure calls to agents running on the platform.
    * :ref:`Status <Platforms-Agents-Status-Endpoints>`: Endpoints for determining the status information for an agent
      running on the platform.
    * :ref:`Tag <Platforms-Agents-Tag-Endpoints>`: Endpoints for getting, setting, and deleting the tag of agents.

.. attention::
    All Platforms Agents endpoints require a JWT bearer token obtained through the
    ``POST /authenticate`` or ``PUT /authenticate`` endpoints.

--------------

GET /platforms/:platform/agents
===============================

Return routes for the agents installed on the platform.

Accepts a two query parameters:

* ``agent-state`` accepts one of three string values:
    - *"running"* (default): Returns only those agents which are currently running.
    - *"installed"*: Returns all installed agents.
    - *"packaged"*: Returns filenames of packaged agents on the platform which can be installed.
* ``include-hidden`` (default=False): When True, includes system agents which would not normally be displayed by vctl status.
* ``tag`` (optional): A shell-style pattern matched against each agent's tag (``fnmatch`` rules). ``tag=*`` selects every
  agent that has a tag; agents without a tag never match.
* ``regex`` (optional): A regular expression searched against each agent's VIP identity.

``tag`` and ``regex`` combine by intersection and may be used with either ``agent-state`` value.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response:
---------

* **With valid BEARER token on success:** ``200 OK``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "route_options": {
                    "<vip_identity>": "/platforms/:platform/agents/:vip_identity",
                    "<vip_identity>": "/platforms/:platform/agents/:vip_identity"
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

------------------------------------------------------------------------------------------

GET /platforms/:platform/agents/:vip-identity
=============================================

Return routes for the supported endpoints for an agent installed on the platform.
Currently implemented endpoints include :ref:`RPC <Platforms-Agents-Rpc-Endpoints>`.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response:
---------

* **With valid BEARER token on success:** ``200 OK``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "route_options": {
                    "<vip_identity>": "/platforms/:platform/agents/:vip_identity/<endpoint1_name>",
                    "<vip_identity>": "/platforms/:platform/agents/:vip_identity/<endpoint2_name>"
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

--------------

.. _Platforms-Agents-Selection:

Selecting several agents at once
================================

The ``:vip-identity`` segment of the ``running``, ``enabled``, ``status`` and ``health`` routes may be the wildcard
``-``, in which case the request addresses a selection of agents chosen by query parameters, in the same way the
devices endpoints use ``-`` for a topic segment:

* ``tag=<pattern>``: a shell-style pattern matched against each agent's tag (``fnmatch`` rules). ``tag=*`` is every agent
  that has a tag; agents without a tag never match.
* ``regex=<pattern>``: a regular expression searched against the VIP identity.
* ``include-hidden`` (default=false): also consider the platform's own services (running peers that are not installed
  agents). They are excluded by default so that a broad pattern cannot stop or disable the platform itself.

Parameters combine by intersection. The response is a JSON object keyed by VIP identity, one entry per selected agent,
using the same fields as the single-agent form of the route. A selection that matches no agent returns ``200 OK`` with
an empty object. For ``PUT`` and ``DELETE`` the action is applied to each selected agent independently; each entry
gains an ``error`` field, ``null`` on success or a message for that agent, and one agent's failure does not stop the
others. Platform services selected with ``include-hidden`` cannot be started, stopped or prioritized and report an
error. Writes to a selection are idempotent: ``PUT .../-/running`` starts only the agents that are not running (or
restarts all of them with ``restart=true``) and ``DELETE .../-/running`` stops only those that are.

Example: stop every agent that carries a tag beginning with ``ilc``::

    DELETE /vui/platforms/:platform/agents/-/running?tag=ilc*

    {
        "ilc.agent": {"running": false, "error": null},
        "ilc.scheduler": {"running": false, "error": null}
    }

``GET /platforms/:platform/agents/-`` lists the routes that accept a selection. The ``tag`` route is deliberately not
among them; tags are set and removed one agent at a time.

.. toctree::
    :hidden:

    ConfigStore <agents/config-endpoints>
    Enabled <agents/enabled-endpoints>
    Health <agents/health-endpoints>
    RPC <agents/rpc-endpoints>
    Running <agents/running-endpoints>
    Status <agents/status-endpoints>
    Tag <agents/tag-endpoints>
