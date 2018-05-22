Welcome to ``Presence Manager`` Service documentation!
======================================================

Overview
--------
``Presence Manager`` service manage the presence of users in a xmpp chatroom. This service supports Openfire xmpp server. This service use `SleekXMPP`_ library as xmpp client.

This document describes how to send data to the service and the returning response to the client.

Communication between client and service is done through a message broker, Mosquitto, that implements the MQTT protocol versions 3.1 and 3.1.1. MQTT provides a lightweight method of carrying out messaging using a publish/subscribe model. 
Currently is in the ``version 1.0``.

.. _SleekXMPP: https://github.com/fritzy/SleekXMPP 

Presence Manager Requests
-------------------------
To send requests to Presence Manager is necessary to subscribe the topic ``/chatManager/requests.``

To receive the response of the requests made is necessary to subscribe the topic ``/chatManager/response``. 

Every requests are made publishing a message in the broker in the topic ``/chatManager/requests``.

The request and response data have JSON formatting and contains a type to differentiate the requests.

Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Resources
---------
There is only one main resource. 


==============
Enter chatroom
==============
The type of this request is ``enterChatRoom``. This request allows listening the users' presence in a specific chatroom. 

- Request Body
    The following fields are mandatory.

    :class:`type`
    - The type of the request. Type **str**.

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

- Response Body
    {'type': 'enterChatRoom', 'message': 'successfuly'}


==============
Leave chatroom
==============
The type of this request is ``leaveChatRoom``. This request causes the service to stop listening for changes in the users' presence in a specific chatroom.

- Request Body
    The following fields are mandatory.

    :class:`type`
    - The type of the request. Type **str**.

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

- Response Body
    {'type': 'leaveChatRoom', 'message': 'successfuly'}

============
Get Presence
============
The type of this request is ``getPresence``. This request allows to retrieve the users' presence in a specific chatroom.

- Request Body
    This request only have one field and it is mandatory.

    :class:`chat_room_jid`
    - The chatroom jid. Type **str**.

- Response Body
    {'type': 'getPresence', 'message': presence_values}


Error Handling
--------------
On all requests if an error occurs it is returned a json with the following format::

    {'type': request type,
     'message'  : message,
     'error_type' : error_hint
     }

The ``type`` identifies the request that triggered the error, the ``message`` indicates that an error occurred and the ``error_type`` is a hint to understand the error.

- ``chatRoom`` - Internal database error performing an chatroom query.

- ``chatPresence`` - nternal database error performing an chatpresence query.

- ``createChatRoom`` - Internal database error performing an chatroom insert.

- ``deleteChatroom`` - Internal database error performing an chatroom delete.





Request Examples
----------------
Here we provide examples for each request. 

    ::

        publish("chatManager/requests", {'type':'getPresence', 'chat_room_jid': '1111@conference.deti-es-04.ua.pt'})

    ::

        publish("chatManager/requests", {'type':'leaveChatRoom', 'chat_room_jid': '1111@conference.deti-es-04.ua.pt'})

    ::

        publish("chatManager/requests", {'type':'enterChatRoom', 'chat_room_jid': '1111@conference.deti-es-04.ua.pt'})



    