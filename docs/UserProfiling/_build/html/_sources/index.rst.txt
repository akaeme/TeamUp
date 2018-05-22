
Welcome to ``UserProfiling`` Service documentation!
===================================================

Overview
--------
``UserProfiling`` service is a Restful API that manage user's information.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using POST, GET and DELETE methods. Both request and response are formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.0``.

UserProfiling Requests
----------------------
Events requests can assume multiple types according to the desired operation.
The response body has JSON formatting such as post requests.
Only ``GET/POST/DELETE`` HTTP request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``GET`` and ``DELETE``

UserProfiling Authentication
----------------------------
``UserProfiling`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

UserProfiling Authorization
---------------------------

``UserProfiling`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5007/UserProfiling/v1.0/authorization_managment/

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


Resource
--------
There is only one main resource, that only allows ``POST`` and ``DELETE`` and ``GET`` requests.

=============
POST Requests
=============
The POST requests allows mainly to execute 2 operations over the database: the first one is related to the insertion of a new user according to a set of attributes described below; the second one is related to
the update of an existing user on the database. Internally the decision of the operation is made according to the method described in request. The method can be of 2 types:


^^^^^^
Create
^^^^^^
The user can be created using the method ``create`` ::

    http://127.0.0.1:5007/userProfiling/v1.0/userProfile/create

- Request body
    The following fields are allowed and one of them is optional.

    :class:`user_id`
    - The user id. Type **int**.

    :class:`username`
    - (Optional) The username of the user. Type **str**.

    :class:`mail`
    - The mail of the user. Type **str**.

    :class:`tlm`
    - The mobile number of the user. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response body
    Returns a ``ack`` if the user is created successfully. ::

        {'ack': 'true'}


^^^^^^
Update
^^^^^^
This method allows to update an user previously created using the method ``update``. ::

    http://127.0.0.1:5007/userProfiling/v1.0/userProfile/update


- Request body
    The following fields are allowed and one of them is optional.

    :class:`user_id`
    - The user id. Type **int**.

    :class:`username`
    - (Optional) The username of the user. Type **str**.

    :class:`mail`
    - The mail of the user. Type **str**.

    :class:`tlm`
    - The mobile number of the user. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response body
    Returns a ``ack`` if the user is successfully updated. ::

    {'ack': 'true'}

===========
GET Request
===========
The ``GET`` request allows to get all the user's information. ::

     http://127.0.0.1:5007/userProfiling/v1.0/userProfile/

- Request body
    The only field is mandatory.

    :class:`user_id`
    - The user id. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns the user's information. ::

    {'userProfile': [1234, 'ruioliveiraz', 'rui@ua.pt', 34566, 0], 'ack': 'true'}

==============
DELETE Request
==============
The ``DELETE`` request allows to delete an user from the database. ::

    http://127.0.0.1:5007/userProfiling/v1.0/userProfile/

- Request body
    The only field is mandatory.

    :class:`user_id`
    - The user id. Type **int**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    Returns a ``ack`` if the user is successfully deleted. ::

    {'ack': 'true'}

Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {"error": error type,
     "msg"  : message,
     "code" : HTTP code}

The ``errorType`` refers to the entity/method that triggered the error and the ``message`` is a hint to understand
the error.

- ``Create`` - Internal database error performing an user insert.

- ``Update`` - Internal database error performing an user update.

- ``Get`` - Internal database error performing an user get info.

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

- ``POST``
    ::

        requests.post('http://127.0.0.1:5007/userProfiling/v1.0/userProfile/create', json={'user_id': 1234, 'username':'teamup' ,'mail': 'teamup@ua.pt', 'tlm': 123455 , 'access_token':'hello_world'})


    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": 1234, "username":"teamup" ,"mail": "teamup@ua.pt", "tlm": 123455, "access_token":"hello_world"}' http://127.0.0.1:5007/userProfiling/v1.0/userProfile/create


    ::

        r = requests.post('http://127.0.0.1:5007/userProfiling/v1.0/userProfile/update', json={'user_id': 1234, 'username':"ruioliveiraz" ,'mail': 'rui@ua.pt', 'tlm': 34566 , 'access_token':'hello_world'})


    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": 1234, "username":"ruioliveiraz" ,"mail": "rui@ua.pt", "tlm": 34566 , "access_token":"hello_world"}' http://127.0.0.1:5007/userProfiling/v1.0/userProfile/update


- ``GET``
    ::

       r = requests.get('http://127.0.0.1:5007/userProfiling/v1.0/userProfile/mobile', json={'user_id': 1234, 'access_token':'hello_world' })

    ::

        curl -X GET -G http://127.0.0.1:5007/userProfiling/v1.0/userProfile/mobile -d user_id=1234 -d access_token=helloworld

    ::

       r = requests.get('http://127.0.0.1:5007/userProfiling/v1.0/userProfile/profile', json={'user_id': 1234, 'access_token':'hello_world' })

    ::

        curl -X GET -G http://127.0.0.1:5007/userProfiling/v1.0/userProfile/profile -d user_id=1234 -d access_token=helloworld

- ``DELETE``
    ::

        r = requests.delete('http://127.0.0.1:5007/userProfiling/v1.0/userProfile/', json={"user_id": 1234, 'access_token':'hello_world'})

    ::

        curl -X DELETE -G 'http://127.0.0.1:5007/userProfiling/v1.0/userProfile/' -d user_id=1234 -d access_token=helloworld






