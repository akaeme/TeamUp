Welcome to ``SMS Manager`` Service documentation!
=================================================

Overview
--------
``SMS Manager`` service is a RestFul API that sends SMS using PLIVO's API.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using its methods. The response is formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.1``.

SMS Manager Requests
--------------------
SMS Manager requests can only assume one type.
The request body must have JSON formatting.
The request data is appended on the body for ``POST`` requests. The response body has JSON formatting such as post requests.
Only ``POST`` http request methods are allowed.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

SMS Manager Authentication
--------------------------
``SMS Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

SMS Manager Authorization
-------------------------
``SMS Manager`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5002/smsManager/v1.1/authorization_managment/

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
There is only one main resource, that only allows ``POST`` requests. 

============
POST Request
============
The ``POST`` request allows to send SMSs given a list of phones number::

    http://127.0.0.1:5001/smsManager/v1.1/sendMessage

- Request Body
    The following fields are mandatory.

    :class:`mobile_nr_list`
    - List of phones number. Type **int**.

    :class:`message`
    - Content of the message. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::
     {'ack': 'false'}

HTTP code error::

    +---------------+------------------------+
    | HTTP  Code    |      Description       |
    +---------------+------------------------+
    |     400       |  Bad Request           |
    +---------------+------------------------+

The following message is returned when the ``OAuth 2.0`` is not provided: {"message": "The browser (or proxy) sent a request that this server could not understand."}

The following message is returned when the ``OAuth 2.0`` is not valid, meaning that you aren't authorized: {'message': "You don't have the permission to access the requested resource. It is either read-protected or not readable by the server."}

Request Examples
----------------
Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

    ::

        requests.get('http://127.0.0.1:5015/smsManager/v1.1/sendMessage/', json={'mobile_nr_list': ['969857311', '969857311'], 'message': 'Hi from TeamUp!', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{'mobile_nr_list': ['969857311', '969857311'], 'message': 'Hi from TeamUp!', 'access_token': 'helloworld'}' http://127.0.0.1:5015/smsManager/v1.1/sendMessage/


        