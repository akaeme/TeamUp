.. Weather Service documentation master file, created by
   sphinx-quickstart on Thu Oct 26 11:46:13 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ``Weather Proxy`` Service's documentation!
=================================================

Overview
--------
``Weather Proxy`` API is a service that provides a 10 day weather forecast per location and a precise temperature for a given day and
geographic coordinates.
Our service works as proxy that communicate with two micro services and gives the mean of temperature of this two micro services,
to reach more precise values. This micro services are: ``OpenWeatherMap`` API and ``Wunderground`` API
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using POST and GET methods. Both request and response are formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.0``.

Weather Proxy  Requests
-----------------------
``Weather Proxy Requests``` can assume multiple types according to the desired operation.
Only ``GET/POST/DELETE`` http request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``GET``.
The request and response body have JSON formatting.

Weather Proxy Authentication
----------------------------
``Weather Proxy`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Weather Proxy Authorization
----------------------------
``Weather Proxy`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is autenticated.
Weather needs to communicate with two or more services(OpenWeather and UndergroundWeather), and acts as a client for both.  Before any communication gets the OAuth 2.0 token using the same method as described before.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5008/weatherproxy/v1.0/authorization_managment/

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
        An interface that provides 2 methods: one `GET` and one `POST`. The `GET` objective is provide a way to get the grant token and then exchange the grant with a `OAuth 2.0` token by calling the `POST`. Those methods were implemented by the library that the service use: flash oauthlib available at `github`_.

        .. _github: https://github.com/lepture/flask-oauthlib

Resources
---------
The two main resources of this service are the ``Proxy`` and the ``AlarmManager``. Both export methods according to its context.
and there are a relation between ``API`` Resources and the ``HTTP`` Request methods.

Proxy Resource
--------------
Proxy requests can assume multiple types according to the desired operation.
The request body must have ``JSON`` formatting. The request body also have JSON formatting.
All the request parameters are appended to the ``POST/GET`` method body.

  +------------------+---------------------------+
  | HTTP  Methods    |     API Methods           |
  +------------------+---------------------------+
  |     POST         | * post Weather            |
  +------------------+---------------------------+

=======
Weather
=======

This method allow to ``get`` the temperature and the atmospheric conditions::

    http://127.0.0.1:5008/weatherproxy/v1.0/

- Request Body
    The following fields are allowed.

    :class:`day`
    - The number of the pretend day. Type **str**.

    :class:`hour`
    - The hour to search the weather. Type **str**.

    :class:`lat`
    - The latitude of location. Type **str**.

    :class:`long`
    - The longitude of location. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.


- Response Body
    It contains the temperature, atmospheric conditions at the  hour and the day specified in the requested body::

    Example::

        {"hour": "22", "temp": 8.935, "condition": "Clear", "day": "9"}


Alarm Manager Resource
-----------------------
This resource provides a group of methods to support the ``alarm process`` when a temperature is ``higher`` or ``lower`` than a defined ``threshold``. This process is make with the implementation
of one ``job builder`` that runs once every ``hour`` to check temperature changes.

  +------------------+--------------------------------+
  | HTTP  Methods    |     API Methods                |
  +------------------+--------------------------------+
  |     POST         | * create Alarm Weather         |
  +------------------+--------------------------------+
  |     GET          | * get Alarm Weather by ID      |
  |                  |--------------------------------|
  |                  | * get Alarm Weather            |
  +------------------+--------------------------------+

====================
Create Alarm Weather
====================
This method allows to ``create`` the geographic coordinates (latitude and longitude) and the schedule associated to a specific event::

    http://127.0.0.1:5008/alarmWeather/v1.0

- Request Body
    The following fields are allowed.

    :class:`datetime`
    - The decision data of the event. This data as following format - 11:00 16/11/2017.

    :class:`lat`
    - The latitude coordinates of the event.

    :class:`long`
    - The longitude coordinates of the event.

    :class:`id`
    - The id of the event in question.

     :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

 Example::

        {'datetime': '11:00 16/11/2017',
        'lat': '40.63036952784689',
        'long': '-8.657569885253906',
        'id': '1',
        'access_token':'helloworld'}



=============
Alarm Weather
=============
This method allows to ``get`` the ``two temperatures values`` of the job weather. The value of ``first temperature`` is the temperature preview at the `first moment``.
If this value passes the define ``threshold``, then there ìs a new temperature higher then the first. So this is the ``second temperature``. In next job, the temperature
number one is gonna be update to the value of the second temperature.::

    http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW

- Request Body
    The only filed is mandatory.

     :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    It contains the two temperatures (TEMP1 and TEMP2), the job ID and the event ID associated ::

    Example::

        {"Alarm_Weather": [10,15,1,1]}


====================
Alarm Weather By ID
====================
This method is similar to the Alarm Weather, but in this case allows to ``get`` the  ``two temperatures values`` of the job weather by the ``event ID``.::

    http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW_ID

- Request Body
    The following fields are allowed.

    :class:`event_id`
    - The ID of the event. Type **int**.

     :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    It contains the two temperatures (TEMP1 and TEMP2), the job ID correspond to the event_id ::

    Example::

        {"Alarm_Weather": [10,15,1]}



Request Examples
----------------
Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

- ``Proxy Resource``
    - ``POST``
    Weather::
        requests.post('http://127.0.0.1:5008/Proxy', json={'day': 22, 'hour': 22, 'lat': '40.63036952784689', 'long' : '-8.657569885253906','access_token': 'helloworld'})

    ::


         curl -H "Content-Type: application/json" -X POST -d '{'day': 22, 'hour': 22, 'lat': '40.63036952784689', 'long' : '-8.657569885253906','access_token': 'helloworld'}' http://127.0.0.1:5008/Proxy


- ``Alarm Manager Resource``
    - ``POST``
    Alarm Weather::
        requests.post('http://127.0.0.1:5008/alarmWeather/v1.0', json={'datetime': '11:00 16/11/2017', 'lat': '40.63036952784689', 'long' : '-8.657569885253906', 'id': '1','access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{'datetime': '11:00 16/11/2017', 'lat': '40.63036952784689', 'long' : '-8.657569885253906', 'id': '1','access_token': 'helloworld'}' http://127.0.0.1:5008/alarmWeather/v1.0

    - ``GET``
    Alarm Weather By ID::
        requests.get('http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW_ID', params={'event_id': 3, 'access_token': 'helloworld'})

    ::

        curl -X GET -G http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW_ID -d event_id= 3 -d access_token=helloworld


    Alarm Weather::
        requests.get('http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW', params={access_token': 'helloworld'})

    ::

        curl -X GET -G  http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW -d access_token=helloworld


Error Handling
--------------
The ``errorType``  refers to the entity/method that triggered the error and the ``message`` is a hint to understand the error.::

    {"error": errorType,
     "msg": message,
     "code": HTTP code}

- ``weather_change`` - Error in weather_change resource.

- ``No forecast available`` - Error that occurs when the day present on request body is not within the limits of the forecast.


The following message is returned when the ``OAuth 2.0`` is not provided: {"message": "The browser (or proxy) sent a request that this server could not understand."}

The following message is returned when the ``OAuth 2.0`` is not valid, meaning that you aren't authorized: {'message': "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server."}