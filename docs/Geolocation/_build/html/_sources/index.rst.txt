Welcome to ``Geolocation`` Service's documentation!
===================================================

Overview
--------
``Geolocation`` service is a Restful API that gets the latitude and longitude on a pre defined parameters. It also provides a couple of methods related to the coordinates processing.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using its methods. The response is formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.0``.

Geolocation Requests
--------------------
Geolocation requests can assume multiple types according to the desired operation.
Only ``GET/POST/DELETE`` HTTP request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``DELETE`` and ``GET``. The response body have JSON formatting.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Geolocation Authentication
--------------------------
``Geolocation Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Geolocation Authorization
-------------------------
``Geolocation`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is autenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5004/geolocation/v1.0/authorization_managment/

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

===========
GET Request
===========
The ``GET`` request allows to get the latitude and longitude according to the specified address, get the last
position of an user or look up for a city and zone given the latitude and longitude::

   http://127.0.0.1:5004/geolocation/v1.0/geocode
   http://127.0.0.1:5004/geolocation/v1.0/position
   http://127.0.0.1:5004/geolocation/v1.0/lookup

- Request Body

    - Geocode
        The following fields are mandatory.

        :class:`address`
        - The address to be converted into coordinates. The address can assume values like cities names, streets,
        touristic points. Type **str**.

        :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

        - Response Body
            Returns the latitude and longitude::

            {'ack': 'true', 'msg': {'lat': 40.6405055, 'long': -8.6537539}}

    - Position
        The following fields are mandatory.

        :class:`user_id`
        - The id of an user. Type **str**.

        :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

        - Response Body
            Returns the latitude and longitude::

            {'ack': 'true', 'msg': {'lat': '2.0', 'lng': '2.0', 'timestamp': '20:26:40 02/11/2017'}}

    - LookUp
        The following fields are mandatory.

        :class:`lat`
        - The latitude of a location. Type **str**.

        :class:`lng`
        - The longitude of a location. Type **str**.

        :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

        - Response Body
            Returns the latitude and longitude::

            {'ack': 'true', 'msg': {'local_name': local_name, 'city': 'city'}}

============
POST Request
============
The ``POST`` request allows to execute 2 operations over the database: the first one is related to the insert of a new user ans its geolocation information, according to a set of attributes described below; The second one is related to the update an existing user on the database. With these 2 operations the service can maintain a continuous track of the users::

    http://127.0.0.1:5004/geolocation/v1.0/

Internally the decision of the operation is made in a simple way, if the user exists in the database of the service, an
update is made, otherwise the insertion is made.
All the necessary parameters are receipt with the exception of the datetime that is generated by the service for
internal purposes.

- Request Body
    The following fields are mandatory and shared between the two operations.

    :class:`user_id`
    - The id of an user. Type **str**.

    :class:`lat`
    - The latitude of the user. Type **str**.

    :class:`lng`
    - The longitude of the user. Type **str**.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns an ack::

    {'ack': 'true'}

==============
DELETE Request
==============
The ``DELETE`` request allows to delete an user from the database::

    http://127.0.0.1:5004/geolocation/v1.0/

- Request Body
    The following fields are mandatory.

    :class:`user_id`
    - The id of an user. Type **str**.

    :class:`access_token`
        - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns a list of friends::

    {'ack': 'true'}

Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {'error': error type,
     'msg'  : message,
     'code' : HTTP code}

The ``error type`` refers to the entity/method that triggered the error and the ``message`` is a hint to understand
the error.

- ``Geocode`` - Address not found.

- ``Position`` - Internal database error performing an user query.

- ``Create`` - Internal database error performing an user insert.

- ``Update`` - Internal database error performing an user update.

- ``Delete`` - Internal database error performing an user delete.

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

- ``GET``
    Geocode, Position and LookUp::

        requests.get('http://127.0.0.1:5004/geolocation/v1.0/geocode', params={'address': 'Porto', 'access_token': 'helloworld'})

        requests.get('http://127.0.0.1:5004/geolocation/v1.0/position', params={'user_id': '1234', 'access_token': 'helloworld'})
        
        requests.get('http://127.0.0.1:5004/geolocation/v1.0/lookup', params={'lat': '40.640506', 'lng': '-8.653754', 'access_token': 'helloworld'})

    ::

        curl -X GET -G http://127.0.0.1:5004/geolocation/v1.0/geocode -d address=Porto -d access_token=helloworld
        
        curl -X GET -G http://127.0.0.1:5004/geolocation/v1.0/position -d user_id=1234 -d access_token=helloworld
        
        curl -X GET -G http://127.0.0.1:5004/geolocation/v1.0/lookup -d lat=40.640506 -d lng=-8.653754 -d access_token=helloworld

- ``POST``
    Create or Update user position::

        requests.post('http://127.0.0.1:5004/geolocation/v1.0/', json={'user_id': '1234', 'lat': '2.0', 'lng': '2.0', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": 1234, "lat": 3.0, "lng": 2.0, "access_token": "helloworld"}' http://127.0.0.1:5004/geolocation/v1.0/

- ``DELETE``
    Delete User::

        requests.delete('http://127.0.0.1:5004/geolocation/v1.0/', params={'user_id': '1234', 'access_token': 'helloworld'})

    ::

        curl -X DELETE -G http://127.0.0.1:5004/geolocation/v1.0/ -d user_id=1234 -d access_token=helloworld