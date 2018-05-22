Welcome to ``Locations Manager`` Service's documentation!
=========================================================

Overview
--------
``Locations Manager`` API is a service that manage locations in a wide range of situations.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using POST and GET methods. Both request and response are formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.1``.

Location Manager Requests
-----------------------
``Locations Manager Requests`` can assume multiple types according to the desired operation.
Only ``GET/POST/DELETE`` http request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``GET``. 
The request and response body have JSON formatting.

Resources
---------
The two main resources of this service are the ``EventLocation`` and the ``Voting``. Both export methods according to its context,
and there are a relation between ``API`` Resources and the ``HTTP`` Request methods. For instance, to get all the locations
associated to a event, as the verb says,  it must be done a ``HTTP`` Request ``get``, passing the user event_id.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Location Manager Authentication
----------------------------
``Location Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Location Manager Authorization
----------------------------
``Location Manager`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5005/locationManager/v1.1/authorization_managment/

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


EventLocation Resource
------------------------
This resource provides a group of methods to handle all the operations related with locations, from the simplest to the
most complex, using generic and ``modular`` methods.

Resource Map::

    +---------------+---------------------------+
    | HTTP  Methods |     API Methods           |
    +---------------+---------------------------+
    |     POST      | * create Event Location   |
    +---------------+---------------------------+
    |    DELETE     | * delete Event Location   |
    +---------------+---------------------------+

=====================
Create Event Location
======================
This call allows to ``create`` all information associated to an event.::

   http://127.0.0.1:5005/locationManager/v1.1/Event_location

- Request Body
    The following fields are mandatory.

    :class:`event_id`
    - Get the ID of event received from the body.

    :class:`timestamp`
    - The epoch timestamp that defines the schedule of the event.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


======================
Delete Event Location
======================
This call allows to ``delete`` all information associated to an event.::

    http://127.0.0.1:5005/locationManager/v1.1/Event_location/

- Request Body
    The following fields are mandatory.

    :class:`event_id`
    - Get the ID of event received from the body.

    :class:`timestamp`
    - The epoch timestamp tha defines the schedule of the event.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


Voting Resource
----------------------
This resource provides only one method to handle all the operations related with events.

Resource Map::

    +------------------------------------------+
    | HTTP  Methods |     API Methods          |
    +---------------+--------------------------+
    |               | * get all locations      |
    |               |--------------------------|
    |      GET      | * get most voted         |
    |               |--------------------------|
    |               | * get Three most voted   |
    +---------------+--------------------------+
    |     POST      | * add Location           |
    |               | * add Vote               |
    +---------------+--------------------------+

===================
All Locations
===================
This method allows to ``get`` all information (latitude, longitude, votes and city) about all locations of an event. The return result is sorted by the ``priority`` field::

   http://127.0.0.1:5005/locationManager/v1.1/voting/all_locations

- Request Body
    The following fields are mandatory.

    :class:`event_id`
    - The id of an event, it is generated by the service.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns a list of all locations associated to the event_id::

    {'locations': [(lat,long,votes,city)]}

===================
Most Voted
===================
This method allows to ``get`` the ``most voted`` location for an event::

    http://127.0.0.1:5005/locationManager/v1.1/voting/most_voted

- Request Body
    The following fields are mandatory.

    :class:`event_id`
    - The id of an event, it is generated by the service.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns the geographic coordinates and votes associated to the most voted location of an event::

     {'locations': [(lat,long,votes,city)]}


===================
Three most voted
===================
This method allows to ``get`` the ``three most voted`` location for an event by ``city name``::

    http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted

- Request Body
    The following fields are mandatory.

    :class:`zone`
    - The name of city of the location for an event.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns a list of the three most voted locations associated to the event_id by zone::

    {'locations': [(lat,long,votes,city),(lat_1,long_1,votes_1,city_1),(lat_2,long_2,votes_2,city_2)]}


===================
Create Location
===================
This method allows to ``create`` the location associated to an event to begin the voting process.::

    http://127.0.0.1:5005/locationManager/v1.1/voting/add_location

- Request Body
     The following fields are mandatory.

    :class:`event_id`
    - The ID that references the event .

    :class:`lat`
    -  The latitude of the location coordinates.

    :class:`long`
    - The longitude of the location coordinate.

    :class:`city`
    - The name of city of the location for an event.

     :class:`priority`
    - The priority associated with location introduce on request body.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns an ack when the creation process succeeds::

    {u'ack': u'true'}


===================
Vote
===================
This method allows to ``create`` a vote in a particular location for an event, this is the voting process.::

    http://127.0.0.1:5005/locationManager/v1.1/voting/vote

- Request Body
    The following fields are mandatory.

    :class:`event_id`
    - The ID that references the event .

    :class:`lat`
    - The latitude of the location coordinates.

     :class:`long`
    - The longitude of the location coordinate.

     :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns an ack when the creation process succeeds::

    {u'ack': u'true'}

Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {"error": errorType,
     "msg": message,
     "code": HTTP code}


The ``errorType``  refers to the entity/method that triggered the error and the ``message`` is a hint to understand the error.:


- ``AddLocation`` - Internal database error performing an location insert.

- ``AddEvent`` - Internal database error performing an event_location insert.

- ``DeleteEvent`` - Internal database error performing an location delete by event ID.

- ``Vote`` - Internal database error performing an voting insert.


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

- ``EventLocation Resource``
    - ``POST``
    EventLocation::
        requests.post('http://127.0.0.1:5005/locationManager/v1.1/Event_location', json={'event_id': 3, 'timestamp':'1511046742','access_token': 'helloworld'})

    ::

         curl -H "Content-Type: application/json" -X POST -d '{'event_id': 3, 'timestamp':'1511046742','access_token': 'helloworld'}' http://127.0.0.1:5005/locationManager/v1.1/Event_location


    - ``DELETE``
    EventLocation::
        requests.delete('http://127.0.0.1:5005/locationManager/v1.1/Event_location/', params={'user_id': 3, 'access_token': 'helloworld'})

    ::

         curl -X DELETE -G http://127.0.0.1:5005/locationManager/v1.1/Event_location/ -d user_id=3 -d access_token=helloworld

- ``Voting Resource``
    - ``GET``
    All Locations::
        requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/all_locations', params={'event_id': 3, 'access_token': 'helloworld'})

    ::

        curl -X GET -G http://127.0.0.1:5005/locationManager/v1.1/voting/all_locations -d event_id= 3 -d access_token=helloworld


    Most Voted::
        requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/most_voted', params={'event_id': 3, 'access_token': 'helloworld'})

    ::

        curl -X GET -G http://127.0.0.1:5005/locationManager/v1.1/voting/most_voted -d event_id=3 -d access_token=helloworld


    Three most voted::
        requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted', params={'zone': 'Aveiro', 'access_token': 'helloworld'})

    ::

        curl -X GET -G http:http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted -d zone=Aveiro -d access_token=helloworld

    - ``POST``
    Add Location:
         requests.post('http://127.0.0.1:5005/locationManager/v1.1/voting/add_location', json={'event_id': 3, 'lat': '40,6303','long': '-7,6575',
         'city': 'Aveiro','priority': 2,'access_token': 'helloworld'})

    ::


         curl -H "Content-Type: application/json" -X POST -d '{'event_id': 3, 'lat':'40,6303', 'long': -7,657, 'city': Aveiro, 'priority': 2 ,'access_token': 'helloworld'}' http://127.0.0.1:5005/locationManager/v1.1/voting/add_location

    Add Vote:
        requests.post('http://127.0.0.1:5005/locationManager/v1.1/voting/vote', json={'event_id': 3, 'lat': '40,6303','long': '-7,6575',
        'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{'event_id': 3, 'lat':'40,6303', 'long': -7,657,'access_token': 'helloworld'}' http://127.0.0.1:5005/locationManager/v1.1/voting/vote


