Welcome to ``PushNotification`` Service's documentation!
=========================================================

Overview
--------
``PushNotification`` API is a service that manage push notifications.
This document describes the protocol used to send data to the API and the returning response to the client.

Communication is done over HTTP using POST method. Both request and response are formatted as JSON,
and the content type of both is ``application/json``.

PushNotification Requests
-----------------------
The request body must have JSON formatting. The request body also have JSON formatting.
All the ``POST`` request parameters are appended to the Request Header body.
Only ``POST`` http request method is allowed.

Resource Map::

    +---------------+---------------------+
    | HTTP  Methods |     API Methods     |
    +---------------+---------------------+
    |     POST      | * Push notification |
    +---------------+---------------------+

=================
Push Notification
=================
This call allows to send a ``Push Notification``::

    http://127.0.0.1:5017/pushNotification/v1.0/sendNotification/

- Request Body
    Both fields are mandatory.

    :class:`topic`
    - The id of the topic queue to be published.

    :class:`message`
    - The message content to be sended.

- Response Body
    Returns an ack when the sending process succeeds::

    {u'ack': u'true'}

