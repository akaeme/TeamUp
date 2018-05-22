Welcome to ``Alarm Manager`` Service's documentation!
=====================================================

Overview
--------
``Alarm Manager`` service is a Restful API that has a main objective: to trigger alarms related to the temporal approximation
of an event and its weather conditions.
This document describes the protocol used to send data to the API.

Communication is done over HTTP using POST methods. Request is formatted as JSON, and the content
type is ``application/json``.

Currently is in the ``version 1.0``.

Alarm Manager Requests
----------------------
Alarm Manager requests can only assume two types. 
Only ``POST`` and ``DELETE`` http requests methods are allowed.
The request body must have JSON formatting.
The request data is appended on the body for ``POST`` request. The response body have JSON formatting.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Alarm Manager Authentication
----------------------------
``Alarm Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Alarm Manager Authorization
----------------------------
``Alarm Manager`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Management
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5001/alarmManager/v1.0/authorization_managment/

        - Request Body

            :class:`redirect_uri`
            - The ``url`` where the grant will be redirected. Type **str**.

            :class:`scopes`
            - The ``scope`` is the desired permissions, considering that exists permissions that a client cant get. Type **str**.

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
There is only one main resource, that only allows ``POST`` and ``DELETE`` requests.
For each request, the resource schedule ``4 jobs``, according to the supported alarms:

- Decision datetime

- Weather change

- Reminder (Alert 1 hour before)

- Closed event (When it's time for the event)

The first one runs once, at the decision datetime. It gets the event datetime decision, from the service that handle the event schedules, and schedule the three following jobs.
The seconds one, runs every 1 hour and check for weather drastic changes, it compares the forecast weather at moment
with the forecast done at event creation. Drastic weather changes mean differences above or equal 5 degrees, negatives
or positives. The forecast is obtained by calling the weather service.
The last ones only run once, one hour before and at the event time, respectively.
When triggered all the jobs send a asynchronous request to a endpoint that should handle the alarm notification.

The service is authenticated since it needs to be identified over the others, and as such also has ``OAuth 2.0`` tokens with authorization permissions.
Given 1 job the service internally will need to do a couple of requests:

    - One ``POST`` to the endpoint that handle the notification - Decision datetime notification
    - One ``GET`` to the schedule service to get the final schedule for a event - Get the decision datetime
    - One or Many ``GET`` to the weather service to decide if it is critical change or not.
    - One or Many ``POST`` to the endpoint that handle the notification - Weather change notification
    - One ``POST`` to the endpoint that handle the notification - One hour before, reminder notification
    - One ``POST`` to the endpoint that handle the notification - Event closed notification

The ``POST`` follows always the same structure, it send the information in 2 or 3 fields:

    :class:`type`
    - The ``type`` of the notification. Can assume multiple values(decision, weather, reminder and closed_event). Type **str**.

    :class:`event_id`
    - The `id` of the event. Type **str**.

    :class:`message`
    - The `message` is merely informative, it contains the temperature changes. It can be:
    
        ' - weather forecast decreased x.' and  '- weather forecast increased y.' Type **str**.

============
POST Request
============
The ``POST`` request allows to schedule 1 jobs, that when runs create 3 new jobs in order to handle the 3 possible alarms::

    http://127.0.0.1:5001/alarmManager/v1.0/

- Request Body
    The following fields are mandatory

    :class:`datetime`
    - The ``datetime decision`` of an event. After this datetime the event has a defined schedule. Type **str**.

    :class:`id`
    - The `id` of the event. It will only be used to get information about the weather and the final schedule of the respective event. Type **str**.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}

==============
Delete Request
==============
The ``Delete`` request allows delete the schedules for the jobs related to 1 event::

    http://127.0.0.1:5001/alarmManager/v1.0/

- Request Body
    The following fields are mandatory

    :class:`id`
    - The ``id`` of the event. It is used to get the jobs related to its. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}

Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {'error': error type,
     'msg'  : message,
     'code' : HTTP code}

The ``error type`` refers to the entity/method that triggered the error and the ``message`` is a hint to understand
the error.

- ``Create`` - Internal database error performing an user insert.

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

        requests.post('http://127.0.0.1:5001/alarmManager/v1.0/', json={'datetime': '23:38 26/12/2017', 'id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"id": "10", "datetime": "18:30 25/12/2017", "access_token": "helloworld"}' http://127.0.0.1:5001/alarmManager/v1.0/

- ``DELETE``
    ::

        requests.delete('http://127.0.0.1:5001/alarmManager/v1.0/', json={'id': '7', 'access_token': 'helloworld'})

    ::

        curl -X DELETE -G http://127.0.0.1:5001/alarmManager/v1.0/ -d id=7  -d access_token=helloworld




