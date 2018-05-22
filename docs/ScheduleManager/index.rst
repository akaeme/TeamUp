Welcome to ``Schedule Manager`` Service's documentation!
=========================================================

Overview
--------
``Schedule Manager`` API is a service that manage schedules in a wide range of situations.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using POST and GET methods. Both request and response are formatted as JSON,
and the content type of both is ``application/json``.

Schedule Manager Requests
-------------------------
Schedule requests can assume multiple types according to the desired operation.
The request data is appended on the body for ``POST`` requests and on arguments for ``GET``. 
The response body has JSON formatting such as post requests.
Only ``GET/POST/DELETE`` http request methods are allowed.


Schedule Manager Authentication
-------------------------------
``Schedule Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Schedule Manager Authorization
------------------------------
``Schedule Manager`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5006/scheduleManager/v1.0/authorization_managment/

        - Request Body

            :class:`redirect_uri`
            - The ``url`` where the grant will be redirected. Type **str**.

            :class:`scopes`
            - The ``scope`` is the desired permissions, considering that exists permissions that a client can't get. Type **str**.

            :class:`jwt-bearer`
            - The ``jwt-bearer`` is the token that contain information about the client and permit check if him is authenticated. Type **str**.

        - Response Body
            Return app information::

            {'client_id': '1234','client_secret': '4321'}

        Internally the service gets the client identification when confirm his authenticity by contacting the authentication server.
        A client can have multiple apps and multiple views over the service. 
    - Authorize
        An interface that provides 2 methods: one `GET` and one `POST`. The `GET` objective is provide a way to get the grant token and then exchange the grant with a `OAuth 2.0` token by calling the `POST`. Those methods were implemented by the library that the service use: flask oauthlib available at `github`_.
        
        .. _github: https://github.com/lepture/flask-oauthlib


Resources
---------
The two main resources of this service are the Schedule and the Voting. Both export methods according to its context,
and there are a relation between ``API`` Resources and the ``HTTP`` Request methods. For instance, to get all the schedules
associated to a request, as the verb says,  it must be done a ``HTTP`` Request ``GET``, passing the user request_id.

Schedule Resource
-----------------
This resource provides a group of methods to handle all the operations related with schedules, from the simplest to the
most complex, using generic and ``modular`` methods.

Resource Map::

    +---------------+---------------------+
    | HTTP  Methods |     API Methods     |
    +---------------+---------------------+
    |     GET       | * get Schedules     |
    +---------------+---------------------+
    |     POST      | * create Schedule   |
    |               | * create Request    |
    +---------------+---------------------+
    |    DELETE     | * delete Schedule   |
    |               | * delete Schedules  |
    +---------------+---------------------+

=============
Get Schedules
=============
This call allows to get all information about all ``schedules``::

    http://127.0.0.1:5006/scheduleManager/v1.0/schedule/

- Request Body
    The only field is mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns a list of schedules and correspondent request_id, timestamp, votes and priority::

    [ { "request_id": 123, "timestamp": 123456789, "votes": 10, "priority": 5 } ]

===============
Create Schedule
===============
This method allows to ``create`` a schedule::

     http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule

- Request Body
    The following fields are mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`timestamp`
    - The timestamp of the schedule. Type **int**.

    :class:`priority` 
    - The priority of the schedule. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

    Example::

        { "request_id": 12345,
          "timestamp": "1510238506",
          "priority" : 5}

==============
Create Request
==============
This method allows to ``create`` a Request, which is needed to add a schedule::

     http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postRequest

- Request Body
    The following fields are mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`timestamp`
    - The timestamp of the decision of the schedule. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

    Example::

        { "request_id": 12345,
          "timestamp": "1510238506"}

- Response Body
    Returns an ack when the creation process succeeds::

    {u'ack': u'true'}


===============
Delete Schedule
===============
This method allows to ``delete`` a schedule previously created.::

    http://127.0.0.1:5006/scheduleManager/v1.0/schedule/deleteSchedule

- Request Body
    The following fields are mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`timestamp`
    - The timestamp of the schedule. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns an ack when the deletion process succeeds::

    {"ack": "true"}

================
Delete Schedules
================
This method allows to ``delete`` all schedules previously created that are associated to a request ID.::

    http://127.0.0.1:5006/scheduleManager/v1.0/schedule/deleteAll

- Request Body
    The following fields are mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns an ack when the deletion process succeeds::

    {"ack": "true"}

Resource
--------
This resource provides a group of methods to handle all the operations related with the process of voting and get the most voted schedule for a specific request.

Resource Map::

    +---------------+--------------------------+
    | HTTP  Methods |     API Methods          |
    +---------------+--------------------------+
    |     GET       | * get voted Schedule     |
    +---------------+--------------------------+
    |     POST      | * vote for a Schedule    |
    +---------------+--------------------------+


==============
Voted Schedule
==============
This call allows to get ``the most voted schedule(s)`` associated to a specific request::

   http://127.0.0.1:5006/scheduleManager/v1.0/voting/

- Request Body
    The only field is mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns timestamp and the number of votes for the most voted schedule(s).

    { "request_id": 123, "timestamp": 123456789, "votes": 10, "priority": 5 }

===================
Vote for a schedule
===================
This call allows to ``vote`` for a schedule associated to a specific request::

   http://127.0.0.1:5006/scheduleManager/v1.0/voting/

- Request Body
   The following fields are mandatory.

    :class:`request_id`
    - The id of a request. Type **int**.

    :class:`timestamp`
    - The timestamp of the schedule. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

   Example::

      { "request_id": 12345,
          "timestamp": "1510238506"}

- Response Body
    Returns an ack::

    {"ack": "true"}


Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {"error": errorType,
     "msg": message,
     "code": HTTP code}


The ``errorType``  refers to the entity/method that triggered the error and the ``message`` is a hint to understand the error.:

- ``GetSchedule`` - Internal database error performing a schedule query.

- ``PostSchedule`` - Internal database error performing a schedule insert or the schedule already exists.

- ``DeleteSchedule`` - Internal database error performing a schedule delete.

- ``PostRequest`` - Internal database error performing a request insert or the request already exists.

- ``GetVoting`` - Internal database error performing a voting query.

- ``PostVoting`` - Internal database error performing a voting insert or the schedule does not exist.

Most common errors::

    +---------------+------------------------+
    | HTTP  Code    |      Description       |
    +---------------+------------------------+
    |     400       |  Bad Request           |
    +---------------+------------------------+
    |     403       |  Forbidden             |
    +---------------+------------------------+
    |     405       |  Method Not Allowed    |
    +---------------+------------------------+
    |     500       |  Internal Server Error |
    +---------------+------------------------+


The following message is returned when the ``OAuth 2.0`` is not provided: {"message": "The browser (or proxy) sent a request that this server could not understand."}

The following message is returned when the ``OAuth 2.0`` is not valid, meaning that you aren't authorized: {'message': "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server."}



Request Examples
----------------
Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

- ``POST``
    ::

       requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postRequest/', json={'request_id': 125, 'timestamp': 1510238506, 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{'request_id': 125, 'timestamp': 1510238506, 'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postRequest/

    ::

       requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule/', json={'request_id': 125, 'timestamp': 1510238506, 'access_token':'hello_world'})

    ::
        curl -H "Content-Type: application/json" -X POST -d '{'request_id': 123, 'timestamp': 1510238888, 'priority': 7, 'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule/

    ::

       requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/schedule/', json={'request_id': 8, 'access_token':'hello_world'})

    ::
        curl -H "Content-Type: application/json" -X POST -d '{'request_id': 8,'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/schedule/schedule/

- ``GET``
    ::

       requests.get('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/', json={'request_id': 125, 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X GET -d '{'request_id': 125, 'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/schedule/

    ::

        requests.get('http://127.0.0.1:5006/scheduleManager/v1.0/voting/', json={'request_id': 125, 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X GET -d '{'request_id': 125, 'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/voting/

- ``DELETE``
    ::

       requests.delete('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/', json={'request_id': 125, 'timestamp': 1510238888, 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X DELETE -d '{'request_id': 125, 'timestamp': 1510238888, 'access_token':'hello_world'}' 
        http://127.0.0.1:5006/scheduleManager/v1.0/schedule/







