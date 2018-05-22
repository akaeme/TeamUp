.. UndergroundWeather documentation master file, created by
   sphinx-quickstart on Wed Jan  3 19:09:11 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ``UndergroundWeather`` Service' documentation!
============================================================

Overview
--------
``UndergroundWeather`` API is a service that provides a 10 day weather forecast per location and a precise temperature for a given day and
geographic coordinates. This service communicates with the external API, ``Underground``.

Communication is done over HTTP using its methods. The response is formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.1``.

UndergroundWeather Requests
-----------------------
``UndergroundWeather Requests``  can assume multiple types according to the desired operation.
Only ``GET/POST/DELETE`` HTTP request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``DELETE`` and ``GET``. The response body have JSON formatting.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

UndergroundWeather Authentication
----------------------------------
``UndergroundWeather Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

UndergroundWeather Authorization
----------------------------------
``UndergrounWeather`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5010/Underground/v1.1/authorization_managment/

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
This service had only one resource, the ``Hourly10days``. This resource methods according to its context.
and there are a relation between ``API`` Resources and the ``HTTP`` Request methods.

Hourly10days Resource
----------------

This method allow to get the temperature and the atmospheric conditions for a given day and
geographic coordinates.::

    http://127.0.0.1:5010/Underground/

- Request Body
    The following fields are allowed.

    :class:`lat`
    - The latitude of location. Type **str**.

    :class:`long`
    - The longitude of location. Type **str**.

    :class:`day`
    - The number of the pretend day. Type **str**.

    :class:`hour`
    - The hour of the pretend day. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.


- Response Body
    It contains the temperature, atmospheric conditions at the  hour and the day specified in the requested body::

    Example::

        {"hour": "22", "temp": 8.935, "condition": "Clear", "day": "9"}


Error Handling
----------------

On all requests if an error occurs it is returned a json with the following format::

    {"error": errorType,
     "msg": message,
     "code": HTTP code}


The ``errorType``  refers to the entity/method that triggered the error and the ``message`` is a hint to understand the error.:

- ``Underground`` - Error fetching the prevision.

- ``No forecast available`` - Error that occurs when the day present on request body is not within the limits of the forecast. In this case, the service returns an empty list.

The following message is returned when the ``OAuth 2.0`` is not provided: {"message": "The browser (or proxy) sent a request that this server could not understand."}

The following message is returned when the ``OAuth 2.0`` is not valid, meaning that you aren't authorized: {'message': "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server."}


Request Examples
----------------

Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

- ``Hourly10days Resource``
    - ``POST``
        requests.post('http://127.0.0.1:5010/Underground/', json={'lat': '40.63036952784689', 'long':'-8.657569885253906', 'day': 22, 'hour': 15,'access_token': 'helloworld'})

    ::

         curl -H "Content-Type: application/json" -X POST -d '{'lat': '40.63036952784689', 'long':'-8.657569885253906', 'day': 22, 'hour': 15,'access_token': 'helloworld'}' http://127.0.0.1:5010/Underground/

