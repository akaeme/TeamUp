Welcome to ``Chat Manager`` Service documentation!
==================================================

Overview
--------
``Chat Manager`` service is a RestFul API that manage xmpp chatrooms using Openfire xmpp server. This service use `SleekXMPP`_ library as xmpp client.

This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using its methods. The response is formatted as JSON,
and the content type of both is ``application/json``.

Currently is in the ``version 1.0``.

.. _SleekXMPP: https://github.com/fritzy/SleekXMPP 

Chat Manager Requests
---------------------
Chat Manager requests can only assume 2 types. Only ``POST`` and ``DELETE`` http requests methods are allowed.
The request body must have JSON formatting.
The request data is appended on the body for ``POST`` requests and on arguments for ``DELETE``. The response body has JSON formatting such as post requests.
Every request must contain a valid ``OAuth 2.0``.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Chat Manager Authentication
---------------------------
``Chat Manager`` service is authenticated over an external identify that must be trusted. The service need to be registered on the authentication central server and need to have the credentials. To be authenticated you need 2 steps/requests:

- POST
    - Request: Send the username in order to mention the authentication intention.
    - Response: Receive a nonce.

- GET
    - Request: Send the nonce digest concatenated with the password digest.
    - Response: Receive a JSON Web Token (JWT).

The digest function is ``SHA256``.
For the further requests this ``JSON Web Token`` will be used to confirm the service identity.

Chat Manager Authorization
--------------------------
``Chat Manager`` service provides authorization using ``OAuth 2.0``. The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over a centralized well trusted Authentication Service and only provide access to the service if the client is authenticated.

The service export 2 interfaces to handle all the communications:

    - Authorization Managment
        An interface that allows to create multiple apps on the service. To accomplish this the client must be authenticated and indicate one url to where the grant will be redirected and the desired scopes, to get different views from the service. The service will respond with a `client id` and a `client secret`::

            http://127.0.0.1:5014/chatManager/v1.1/authorization_managment/

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
There is only one main resource, that only allows ``POST`` and ``DELETE`` requests.

=============
POST requests
=============

===============================
Create and configure a chatroom
===============================
The ``POST`` request allows to create and configure a chatroom::

    http://127.0.0.1:5014/chatManager/v1.0/createAndConfigureChatRoom

- Request Body
    The following fields are mandatory:

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`room_name`
    - The chatroom name. Type **str**.

    :class:`room_desc`
    - The chatroom description. Type **str**.

    :class:`logging`
    - Enable public logging. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`invite`
    - Allow occupants to invite others. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`allow_pm`
    - Who can send private messages. Can be ``anyone`` (allows anyone), ``participants`` (allows only participants), ``moderators`` (allows only moderators) and ``none`` 
    (allows nobody). 
    Type **str**.

    :class:`max_users`
    - Maximum number of occupants. Can be ``10``, ``20``, ``30``, ``50``, ``100`` or ``none``. Type **int**.

    :class:`public_room`
    - Make chatroom public. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`persistent_room`
    - Make chatroom persistent. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`moderated_room`
    - Make chatroom moderated. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`members_only`
    - Make chatroom members_only. Can be ``0`` (enable) or ``1`` (disable). Type **int**.

    :class:`disc_JID`
    - Who may discover real JIDs. Can be ``moderators`` (only moderators) and ``anyone`` (nobody). Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}

================
Leave a chatroom
================
The ``POST`` request allows to remove a user from a chatroom::

    http://127.0.0.1:5014/chatManager/v1.0/leaveChatRoom

- Request Body
    The following fields are mandatory:

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`nick`
    - The user's nick. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


=====================
Send message chatroom
=====================
The ``POST`` request allows to send a message to a chatroom::

    http://127.0.0.1:5014/chatManager/v1.0/sendMessage

- Request Body
    The following fields are mandatory:

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`message`
    - The content of a message. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


====================
Send invite chatroom
====================
The ``POST`` request allows to send an invitation to a user to enter the chatroom::

    http://127.0.0.1:5014/chatManager/v1.0/sendInvite

- Request Body
    The following fields are mandatory:

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`user_jid`
    - The user jid. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


===========
Create user
===========
The ``POST`` request allows create an user in xmpp server::

    http://127.0.0.1:5014/chatManager/v1.0/createUser

- Request Body
    The following fields are mandatory

    :class:`username`
    - The user username. Type **str**.

    :class:`password`
    - The user password. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


===============
Set affiliation
===============
The ``POST`` request allows to set an affiliation to user.::

    http://127.0.0.1:5014/chatManager/v1.0/setAffiliation

- Request Body
    The following fields are mandatory

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`user_jid`
    - The user jid. Type **str**.

    :class:`affiliation`
    - The type of affiliation. Can be ``outcast``, ``member``, ``admin``, ``owner``, ``none``. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


===============
Set role
===============
The ``POST`` request allows create an user in xmpp server::

    http://127.0.0.1:5014/chatManager/v1.0/setRole

- Request Body
    The following fields are mandatory

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

    :class:`user_nick`
    - The user nick. Type **str**.

    :class:`role`
    - The type of role. Can be ``moderator``, ``participant``, ``visitor``, ``none``. Type **str**.

    :class:`access_token`
    - The ``access token`` that contains a set of permissions and that was provided by this service. Type **str**.

- Response Body
    {'ack': 'true'}


===============
DELETE requests
===============

=================
Remove a chatroom
=================
The ``DELETE`` request allows to remove a chatroom::

    http://127.0.0.1:5014/chatManager/v1.0/

- Request Body
    The following fields are mandatory

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

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

- ``chatRoom`` - Internal database error performing an chatroom query.  Missing permission to perform this operation, chatroom does not exist.

- ``createAndConfigureChatRoom`` - Internal database error performing an chatroom insert.

- ``removeChatRoom`` - Internal database error performing an chatroom delete. Missing permission to perform this operation, chatroom does not exist.

Most common errors::

    +---------------+------------------------+
    | HTTP  Code    |      Description       |
    +---------------+------------------------+
    |     400       |  Bad Request           |
    +---------------+------------------------+
    |     403       |  Forbidden             |
    +---------------+------------------------+
    |     417       |  Expectation Failed    |
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

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/createUser', json={'username': 1112, 'password': 'mypassword', access_token:'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"username": "teamup", "password": "mypassword", access_token:'hello_world'}' 
        http://127.0.0.1:5014/chatManager/v1.0/createUser

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/createAndConfigureChatRoom', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'room_name': 'TeamUp', 'room_desc': 'My room description', 'logging':1, 'invite':1, 'allow_pm':'anyone', 'max_users': 50, 'public_room': 1, 'persistent_room': 1,'moderated_room': 0, 'members_only': 0, 'disc_JID':'moderators', access_token:'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"chat_room_jid": "50@conference.deti-es-04.ua.pt", "room_name": "TeamUp", "room_desc": "My room description", "logging":1, "invite":1, "allow_pm":"anyone", "max_users": 50, "public_room": 1, "persistent_room": 1,"moderated_room": 0, "members_only": 0, "disc_JID":"moderators", access_token:'hello_world'}' http://127.0.0.1:5014/chatManager/v1.0/createAndConfigureChatRoom

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/sendInvite', json={'user_jid': '1112@deti-es-04.ua.pt/Ruis-MacBook-Pro','chat_room_jid': '50@conference.deti-es-04.ua.pt', access_token:'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_jid": "1112@deti-es-04.ua.pt/Ruis-MacBook-Pro","chat_room_jid": "50@conference.deti-es-04.ua.pt", "access_token":"hello_world"}' http://127.0.0.1:5014/chatManager/v1.0/sendInvite

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/sendMessage', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'message':'heeey', access_token:'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_jid": "1112@deti-es-04.ua.pt/Ruis-MacBook-Pro","chat_room_jid": "50@conference.deti-es-04.ua.pt", "access_token":"hello_world"}' http://127.0.0.1:5014/chatManager/v1.0/sendMessage

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/leaveChatRoom', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'nick':'managerBot', 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"chat_room_jid": "50@conference.deti-es-04.ua.pt", "nick":"managerBot", "access_token":"hello_world"}' http://127.0.0.1:5014/chatManager/v1.0/leaveChatRoom

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/setAffiliation', json={'chat_room_jid': '60@conference.deti-es-04.ua.pt', 'user_jid':'teamup@deti-es-04.ua.pt/teamup', 'affiliation':'outcast', 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"chat_room_jid": "60@conference.deti-es-04.ua.pt", "user_jid":"teamup@deti-es-04.ua.pt/teamup", "affiliation":"outcast", "access_token":"hello_world"}' http://127.0.0.1:5014/chatManager/v1.0/setAffiliation

    ::

        requests.post('http://127.0.0.1:5014/chatManager/v1.0/setRole', json={'chat_room_jid': '60@conference.deti-es-04.ua.pt', 'user_nick':'teamup@deti-es-04.ua.pt/teamup', 'role': 'member', 'access_token':'hello_world'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"chat_room_jid": "60@conference.deti-es-04.ua.pt", "user_nick":"teamup@deti-es-04.ua.pt/teamup", "role": "member", "access_token":"hello_world"}'' http://127.0.0.1:5014/chatManager/v1.0/setRole

- ``DELETE``
    ::

        requests.delete('http://127.0.0.1:5014/chatManager/v1.0/', params={'chat_room_jid': '50@conference.deti-es-04.ua.pt', access_token:'hello_world'})

    ::

        curl -X DELETE -G http://127.0.0.1:5014/chatManager/v1.0/ -d chat_room_jid=50@conference.deti-es-04.ua.pt  -d access_token=helloworld

   




        