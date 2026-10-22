.. _Platforms-Agents-Health-Endpoints:

==================================
Platforms Agents Health Endpoints
==================================

Platforms Agents Health endpoints expose functionality associated with getting health information for
a single agent running on a VOLTTRON platform.

.. attention::
    All Platforms Agents Health endpoints require a JWT bearer token obtained through the
    ``POST /authenticate`` or ``PUT /authenticate`` endpoints.


.. note::

    ``:agent`` may be the wildcard ``-`` to address several agents chosen with the ``tag``, ``regex`` and
    ``include-hidden`` query parameters; the response is then keyed by VIP identity and ``PUT``/``DELETE`` report a
    per-agent ``error``. See :ref:`Platforms-Agents-Selection`.

--------------

GET /platforms/:platform/agents/:agent/health
==============================================

Retrieve health information for the specified agent.

Request:
--------

* Authorization: ``BEARER <jwt_access_token>``

Response:
---------

*  **With valid BEARER token on success:** ``200 OK``
    - Content Type: application/json
    - Body:

      .. code-block:: javascript

            {
                "peer": "<vip_identity>",
                "service_agent": true|false,
                "connected": "<date_time>",
                "last_heartbeat": "<date_time>",
                "message": "<last health message>"
            }

      Only agents currently connected to the platform have health information; a request for any other agent is a
      ``400 Bad Request``.
* **With valid BEARER token on failure:** ``400 Bad Request``
    - Content Type: ``application/json``
    - Body:

      .. code-block:: javascript

            {
                "error": "<Error Message>"
            }

* **With invalid BEARER token:** ``401 Unauthorized``

.. toctree::
    :hidden:

    self
