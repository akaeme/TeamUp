Welcome to ``Application Server`` documentation!
=====================================================

Overview
--------
``Application Server`` provides an abstraction layer on the implementation of a communication system between mutually interacting software applications in a service oriented architecture(SOA).
It should not be treated as a service. Although providing an interface with some methods should be considered as a bus that distribute information between services.
The main capabilities of this component are:
- Routing
- Message Transformation/Message Processing
- Process Choreography
- Protocol Transformation
- Security
Basically acts like a mediator, an enterprise service bus(ESB), between the mobile applicationss and the enterprise services.
The communication on the left side, that is on the input between the mobile applications and the Application Server is always is done over HTTP using POST methods. Request is formatted as JSON, and the content type is ``application/json``. 
On the enterprise side, the communication is mainly done over HTTP, however in some cases it uses mqtt protocol and a message broker - `Mosquitto <https://mosquitto.org/>`_.

Currently is in the ``version 1.0``.

Routing
-------
The ability to channel a request to a particular service provider based on deterministic or variable criteria. For example, the authentication process between the mobile applications and the authentication server is routed by the application server based on requests content. The process is composed by two sequencial requests: the first one must be a POST and the last one a GET request. Based on that the Application Server route the requests to the Authentication Server.

Message Transformation/Message Processing
-----------------------------------------
Convert the structure and format of the incoming business service request to the structure and format expected by the service provider. For example, given a request to vote on a schedule for a specific event the Application Server must receive two parameters: the event identifier(event_id) and a schedule available for the respective event(schedule). The message that the schedule manager service expects is a little bit different and the necessary modifications are done by the Application Server in order to respond successfully to the resolution of the various requests. 

Process Choreography
--------------------
Manage complex business process that requires the coordination of multiple business service to fulfil a single business service request. For example given a request to create an event there are a couple of requests that need to be done over multiple services in order to complete all the subprocesses triggered by the application server, where the input was the user action.
The processes/services are:

- create event              - Events Manager Service
- create chat room          - Chat Manager Service
- look up coordinates       - Geolocation Service
- create datetime schedule  - Schedule Manager Service
- create event              - Location Manager Service
- add each event schedule   - Schedule Manager Service
- add each event location   - Location Manager Service

Protocol Transformation
-----------------------
Accept one type of protocol from the consumer as input (i.e.SOAP/JMS) and communicate to the service provider through a different protocol (i.e. IIOP). For example, given a notification requests related to temporal approximation of an event, the input request is done over HTTP and the appserver process the communication to the Presence Manager Service over MQTT.

Security
--------
Protect enterprise services from unauthorized access. In SOA there are no more silos, services become visible to the entire enterprise through ESB. ESB should access a security manager or authentication and authorization rather than have the direct responsibility.
In relation to the Authentication the Application Server is authenticated over a Authentication Service by a process that contains two requests: the first one is a POST and the last one is a GET. As above the process is the same as in mobile applications.
Every request to the Application Server must contain a valid Json Web Token(JWT) to provide authentication of the entity and allow to the esb confirm it close to the Authentication Service providing also its JWT.
Concerning to the authorization, the application server acts like a client to the enterprise services. Before you can receive commands, the application server must obtain an authorization token for all services it communicates with, except for the authentication server and the presence manager.
The authorization is completed in 3 steps: the first concerns the registration of a redirect url, to receive the grant, and the desired scopes. The second and the third are related to obtaining the grant and the OAuth 2.0 token respectively. The first and second step must contain an ``JWT-Bearer`` to provide authentication and check it over the Authentication Server and only provide access to the service if the client is authenticated.

Application Server Interface
----------------------------
The application server exports multiple methods according to the operations around the context. The structure is simple and follows the next rule: given a base url - http://127.0.0.1:5012/proxy/ - and a desired operation - i.e: login - the final url to materialize is the concatenation of both: http://127.0.0.1:5012/proxy/login. Hereupon, the methods implamented and the respective url are

::
    -   login                   - http://127.0.0.1:5012/proxy/login
    -   create event            - http://127.0.0.1:5012/proxy/create_event
    -   update event            - http://127.0.0.1:5012/proxy/update_event
    -   update user             - http://127.0.0.1:5012/proxy/update_user
    -   search event            - http://127.0.0.1:5012/proxy/search
    -   add user                - http://127.0.0.1:5012/proxy/add_user
    -   add schedules           - http://127.0.0.1:5012/proxy/add_schedule 
    -   add location            - http://127.0.0.1:5012/proxy/add_location
    -   vote datetime           - http://127.0.0.1:5012/proxy/vote_datetime
    -   vote local              - http://127.0.0.1:5012/proxy/vote_local
    -   get groups              - http://127.0.0.1:5012/proxy/get_group
    -   get groups              - http://127.0.0.1:5012/proxy/get_groups
    -   notifications manager   - http://127.0.0.1:5012/proxy/notifications_manager
    -   invite friends          - http://127.0.0.1:5012/proxy/invite_friends
    -   leave group             - http://127.0.0.1:5012/proxy/leave_group
    -   delete group            - http://127.0.0.1:5012/proxy/delete_group
    -   authentication app      - http://127.0.0.1:5012/proxy/authentication_app

Application Server Services
---------------------------
All services are registered in the application server and it establishes communication with them for a certain purpose described by each method of the receiving service. The services are:

- Alarm Manager Service
- Authentication Service
- Chat Manager Service
- Events Manager Service
- Facebook Service
- Geolocation Service
- Location Manager Service
- Presence Manager Service
- Push Notifications Service
- Schedule Manager Service
- Sms Service
- User Profiling Service
- Weather Service

=====
Login
=====
Allows an user to login into the application. Given the request the following services are contacted, by this order:

    - Service - Facebook            - Method: POST http://127.0.0.1:5003/facebook/v1.0/
    - Service - Chat Manager        - Method: POST http://127.0.0.1:5014/chatManager/v1.0/createUser
    - Service - User Profiling      - Method: POST http://127.0.0.1:5007/userProfiling/v1.0/userProfile/create

The application server respective url is::

    http://127.0.0.1:5012/proxy/login

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`fb_access_token`:
    - The ``fb_access_token`` is provided by the facebook and follows the permissions given by the user. Type **str**.

    :class:`expires_in`:
    - The ``time`` in which the token expires. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

============
Create Event
============

Allows an user to create an event with the respective configurations, locations and schedules. Given the request the following services are contacted, by this order:

    - Service - Events Manager      - Method: POST http://127.0.0.1:5002/eventsManager/v1.1/events/create
    - Service - Chat Manager        - Method: POST http://127.0.0.1:5014/chatManager/v1.0/createAndConfigureChatRoom
    - Service - Presence Manager    
    - Service - Geolocation         - Method: GET  http://127.0.0.1:5004/geolocation/v1.0/lookup 
    - Service - Schedule Manager    - Method: POST http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postRequest
    - Service - Location Manager    - Method: POST http://127.0.0.1:5005/locationManager/v1.1/Event_location/
    - Service - Location Manager    - Method: POST http://127.0.0.1:5005/locationManager/v1.1/voting/add_location
    - Service - Schedule Manager    - Method: POST http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule

The application server respective url is::

    http://127.0.0.1:5012/proxy/create_event

- Request Body
    The following fields are mandatory

    :class:`name`
    - The event ``name``. Type **str**.

    :class:`type`
    - The event ``type``, can be 0 to public or 1 to private. The default is 0. Type **int**.

    :class:`activity`
    - The ``activity`` that the event is related to. Type **str**.

    :class:`maxppl`
    - The ``maximum number`` of people that the event allow. Type **int**.

    :class:`minppl`
    - The ``minimum number`` of people that the event allow. The default is 0. Type **int**.

    :class:`owner`
    - The event ``owner``. It has all the permissions over its event. Type **str**.

    :class:`description`
    - The event ``description``, it have a maximum of 140 characters. Type **str**.

    :class:`locations`
    - The ``locations`` are the coordinates(latitude and longitude) where the event may happen. Type list of **str**.

    :class:`locations_priority`
    - The ``locations priority`` are priotirites given by the owner to tie up when two or more locations have the same number of votes. The priority is directly related with the locations, so, the first tuple of locations has a priority with a value on the first position of the list of priorities, and so on. Type list of **str**.

    :class:`schedules`
    - The ``schedules`` are the schedules(epoch timestamp) when the event may happen. Type list of **str**.

    :class:`schedules_priority`
    - The ``schedules priority`` are priotirites given by the owner to tie up when two or more schedules have the same number of votes. The priority is directly related with the schedules, so, the first  schedule has a priority with a value on the first position of the list of priorities, and so on. Type list of **str**.

    :class:`decision`
    - The ``decision`` is the datetime of the decision day, where the event will have a location and a datetime. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true', 'event_id': 'event identifier'}

============
Update Event
============

Allows an user to update an existing event. Only the owner of a event can update it.. Given the request the following services are contacted, by this order:

    - Service - Events Manager      - Method: POST http://127.0.0.1:5002/eventsManager/v1.1/events/update

The application server respective url is::

    http://127.0.0.1:5012/proxy/update_event

- Request Body
    The following fields are mandatory.

    :class:`user_id`
    - The ``user id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`name`
    - The event ``name``. Type **str**.

    :class:`type`
    - The event ``type``, can be 0 to public or 1 to private. The default is 0. Type **int**.

    :class:`activity`
    - The ``activity`` that the event is related to. Type **str**.

    :class:`maxppl`
    - The ``maximum number`` of people that the event allow. Type **int**.

    :class:`minppl`
    - The ``minimum number`` of people that the event allow. The default is 0. Type **int**.

    :class:`owner`
    - The event ``owner``. It has all the permissions over its event. Type **str**.

    :class:`description`
    - The event ``description``, it have a maximum of 140 characters. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

===========
Update User
===========

Allows an user to update its profile. Given the request the following services are contacted, by this order:

    - Service - User Profiling            - Method: POST http://127.0.0.1:5007/userProfiling/v1.0/userProfile/update

The application server respective url is::

    http://127.0.0.1:5012/proxy/update_user

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`username`:
    - The ``username`` is the new username. Type **str**.

    :class:`tlm`:
    - The ``tlm`` is the phone number where the user will be notified. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

============
Search Event
============

Allows an user to search for an event according 3 parameters. Given the request the following services are contacted, by this order and parameters(zone, activity):

    - Service - Geolocation                 - Method: POST http://127.0.0.1:5004/geolocation/v1.0/

        - zone, activity
            - Service - Events Manager      - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
            - Service - Location Manager    - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted
            - Service - Geolocation         - Method: GET http://127.0.0.1:5004/geolocation/v1.0/geocode

        - zone, no activity
            - Service - Events Manager      - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
            - Service - Location Manager    - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted
            - Service - Geolocation         - Method: GET http://127.0.0.1:5004/geolocation/v1.0/geocode

        - no zone, activity
            - Service - Events Manager      - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
            - Service - Location Manager    - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted

        - no zone, no activity
            - Service - Events Manager      - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
            - Service - Location Manager    - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted

The application server respective url is::

    http://127.0.0.1:5012/proxy/search

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`lat`
    - The ``latitude`` of the user. Type **str**.

    :class:`long`
    - The ``longitude`` of the user. Type **str**.

    :class:`zone`
    - The ``zone`` is where the user wants to get events. Type **str**.

    :class:`activity`
    - The ``activity`` which match the event activity, is a filter. Type **str**.

    :class:`distance`
    - The ``distance`` is the range where the user wants to get events, by default is 5 Km. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'event identifier': [name, activity, zone]}


========
Add User
========

Allows an user join a event. Given the request the following services are contacted, by this order:

    - Service - User Profiling              - Method: POST http://127.0.0.1:5002/eventsManager/v1.1/users/
    - Service - ChatManager                 - Method: POST http://127.0.0.1:5014/chatManager/v1.0/sendInvite

The application server respective url is::

    http://127.0.0.1:5012/proxy/add_user

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

============
Add Schedule
============

Allows an user to add or update a schedule to an event. Given the request the following services are contacted, by this order:

    - Service - Schedule Manager            - Method: POST http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule

The application server respective url is::

    http://127.0.0.1:5012/proxy/add_schedule

- Request Body
    The following fields are mandatory

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`timestamp`
    - The epoch ``timestamp`` is the schedule that will be updated or added. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

============
Add Location
============

Allows an user to add a possible location to an event. Given the request the following services are contacted, by this order:

    - Service - Location Manager            - Method: POST http://127.0.0.1:5005/locationManager/v1.1/voting/add_location

The application server respective url is::

    http://127.0.0.1:5012/proxy/add_location

- Request Body
    The following fields are mandatory

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`lat`
    - The ``latitude`` of the new location. Type **str**.

    :class:`long`
    - The ``longitude`` of the new location. Type **str**.

    :class:`priority`
    - The ``priority`` is the priority of the new location. Type **int**.

    :class:`city`
    - The ``city`` is the city of the respective location. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

=============
Vote Datetime
=============

Allows an user to vote on a possible schedule related to an event. Given the request the following services are contacted, by this order:

    - Service - Schedule Manager            - Method: POST http://127.0.0.1:5006/scheduleManager/v1.0/voting/

The application server respective url is::

    http://127.0.0.1:5012/proxy/vote_datetime

- Request Body
    The following fields are mandatory

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`timestamp`
    - The epoch ``timestamp`` is schedule where it will be added a vote. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

==========
Vote Local
==========

Allows an user to vote on a possible location related to an event. Given the request the following services are contacted, by this order:

    - Service - Location Manager            - Method: POST http://127.0.0.1:5005/locationManager/v1.1/voting/vote

The application server respective url is::

    http://127.0.0.1:5012/proxy/vote_local

- Request Body
    The following fields are mandatory

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`lat`
    - The ``latitude`` of the location where it will be added a vote. Type **str**.

    :class:`long`
    - The ``longitude`` of the new location where it will be added a vote. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

==========
Get Groups
==========

Allows an user to get all its groups and some information related to them. Given the request the following services are contacted, by this order:

    - Service - Events Manager            - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/users/

The application server respective url is::

    http://127.0.0.1:5012/proxy/get_groups

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true', 'events': {'public': [], 'private': []}}

=========
Get Group
=========

Allows an user to get a detailed information about one groups where it belongs. Given the request the following services are contacted, by this order:

    - Service - Events Manager            - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/users/
    - Service - Location Manager          - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/all_locations
    - Service - Schedule Manager          - Method: GET http://127.0.0.1:5006/scheduleManager/v1.0/schedule/
    - Service - Weather                   - Method: GET http://127.0.0.1:5008/weatherproxy/v1.0/

The application server respective url is::

    http://127.0.0.1:5012/proxy/get_group

- Request Body
    The following fields are mandatory

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'name': 'event name', 'description': 'event description', 'activity': 'event activity', 'atm': 'number of participant', 'locations': [], 'schedules': [], 'weather': []}

=====================
Notifications Manager
=====================

Its a endpoint url where the services must send notifications requests that should be treated by a central endpoint, which communicates with the necessary around services. Given the request the following services are contacted, by this order and notification type:

    - type - decision
        - Service - Schedule Manager        - Method: GET http://127.0.0.1:5005/locationManager/v1.1/voting/most_voted
        - Service - Location Manager        - Method: GET http://127.0.0.1:5006/scheduleManager/v1.0/voting/
        - Service - Geolocation Manager     - Method: GET http://127.0.0.1:5004/geolocation/v1.0/lookup
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/

    - type - weather
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/

    - type - reminder
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
        - Service - Presence Manager        

    - type - closed_event
        - Service - Events Manager          - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
        - Service - Presence Manager

The application server respective url is::

    http://127.0.0.1:5012/proxy/notifications_manager

- Request Body
    The following fields are mandatory

    :class:`type`
    - The ``type`` of the notification, but follow the especificated above. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`message`
    - The ``message`` of the notification, must be provided when type is weather. Type **str**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

==============
Invite Friends
==============

Allows an user to notify its friends on facebook to join to a specific group. Given the request the following services are contacted, by this order:

    - Service - User Profiling            - Method: GET http://127.0.0.1:5007/userProfiling/v1.0/userProfile/profile
    - Service - Events Manager            - Method: GET http://127.0.0.1:5002/eventsManager/v1.1/events/
    - Service - Facebook                  - Method: GET http://127.0.0.1:5003/facebook/v1.0/

The application server respective url is::

    http://127.0.0.1:5012/proxy/invite_friends

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

===========
Leave Group
===========

Allows an user leave a group where it belongs. Given the request the following services are contacted, by this order:

    - Service - Events Manager            - Method: DELETE http://127.0.0.1:5002/eventsManager/v1.1/users/
    - Service - Chat Manager              - Method: POST http://127.0.0.1:5014/chatManager/v1.0/leaveChatRoom

The application server respective url is::

    http://127.0.0.1:5012/proxy/leave_group

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

============
Delete Group
============

Allows an user to delete an existing group. Given the request the following services are contacted, by this order:

    - Service - Events Manager            - Method: DELETE http://127.0.0.1:5002/eventsManager/v1.1/events/
    - Service - Schedule Manager          - Method: DELETE http://127.0.0.1:5006/scheduleManager/v1.0/schedule/deleteAll
    - Service - Location Manager          - Method: DELETE http://127.0.0.1:5005/locationManager/v1.1/Event_location/
    - Service - Alarm Manager             - Method: DELETE http://127.0.0.1:5001/alarmManager/v1.0/
    - Service - Chat Manager              - Method: POST http://127.0.0.1:5014/chatManager/v1.0/removeChatRoom

The application server respective url is::

    http://127.0.0.1:5012/proxy/delete_group

- Request Body
    The following fields are mandatory

    :class:`user_id`
    - The ``user_id`` is the identifier of an user provided by the facebook. Type **str**.

    :class:`event_id`
    - The ``event id`` is the identifier of an event provided by the Events Manager Service. Type **int**.

    :class:`access_token`
    - The ``access token`` is the JWT provided by the mobile applications to confirm its authentication. Type **str**.

- Response Body
    {'ack': 'true'}

==================
Authentication App
==================

Allows an app to get authenticated. It routes the request to the . Given the request the following services are contacted, by this order and method:

    - POST
        - Service - Authentication          - Method: POST http://127.0.0.1:5013/v1.0/authentication/
    - GET
        - Service - Authentication          - Method: GET http://127.0.0.1:5013/v1.0/authentication/get_token

The application server respective url is::

    http://127.0.0.1:5012/proxy/authentication_app

Request Examples
----------------
Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

    login ::

        requests.post('http://127.0.0.1:5012/proxy/login', json={'user_id': 'facebook_id', 'fb_access_token': 'access_token', 'expires_id': 1234, 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "758941187514413", "fb_access_token": "access_token", "expires_id": "1234", access_token": "helloworld"}' http://127.0.0.1:5012/proxy/login

    create event ::

        requests.post('http://127.0.0.1:5012/proxy/create_event', json={'name': 'fridays', 'type': '1', 'activity': 'football',
        'maxppl': '16', 'minppl': '8', 'owner': '758941187514413', 'description': 'for fun', 'locations': '[['40.6718599', '-7.9047571'], ['40.6715311', '-7.9115649']]', 'locations_priority': '[10,20]', 'schedules': '[' 1515167577', '1515253977']', 'schedules_priority': '[10,20]', 'decision': '23:55 08/01/2018', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"name": "fridays", "type": "1", "activity": "football", "maxppl": "16", "minppl": "8", "owner": "758941187514413", "description": "for fun", "locations": "[['40.6718599', '-7.9047571'], ['40.6715311', '-7.9115649']]", "locations_priority": "[10,20]", "schedules": "[' 1515167577', '1515253977']", "schedules_priority": "[10,20]", "decision": "23:55 08/01/2018", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/create_event

    update event ::

        requests.post('http://127.0.0.1:5012/proxy/update_event', json={'user_id': '758941187514413', 'event_id': '2', 'name': 'new name', 'type': '1', 'activity': 'basket', 'maxppl': '20', 'minppl': '10', 'description': 'for fun', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "758941187514413", "event_id": "2", "name": "new name", "type": "1", "activity": "basket", "maxppl": "20", "minppl": "10", "description": "for fun", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/update_event

    update user ::

        requests.post('http://127.0.0.1:5012/proxy/update_user', json={'user_id': '682109031847376', 'username': 'teamup', 'tlm': '969999999', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "username": "teamup", "tlm": "969999999", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/update_user

    search event ::

        requests.post('http://127.0.0.1:5012/proxy/search', json={'user_id': '682109031847376', 'lat': '40.633774', 'long': '-8.646869', 'activity': 'football', 'zone': 'Aveiro', 'distance': '10', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "lat": "40.633774", "long": "-8.646869", "activity": "football", "zone": "Aveiro", "distance": "10", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/search

    add user ::

        requests.post('http://127.0.0.1:5012/proxy/add_user', json={'user_id': '682109031847376', 'event_id': '2', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "event_id": "2", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/add_user

    add schedules ::

        requests.post('http://127.0.0.1:5012/proxy/add_schedule', json={'timestamp': '17:00 08/01/2018', 'event_id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"timestamp": "17:00 08/01/2018", "event_id": "7", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/add_schedule

    add location ::

        requests.post('http://127.0.0.1:5012/proxy/add_location', json={'event_id': '6', 'lat': '40.640506', 'long': '-8.653754', 'city': 'Aveiro', 'priority': '5', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"event_id": "6", "lat": "40.640506", "long": "-8.653754", "city": "Aveiro", "priority": "5", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/add_location

    vote datetime ::

        requests.post('http://127.0.0.1:5012/proxy/vote_datetime', json={'timestamp': '23:55 08/01/2018', 'event_id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"timestamp": "23:55 08/01/2018", "event_id": "7", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/vote_datetime

    vote local ::

        requests.post('http://127.0.0.1:5012/proxy/vote_local', json={'event_id': '3', 'lat': '40.6303', 'long': '-8.6575', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"event_id": "3", "lat": "40.6303", "long": "-8.6575", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/vote_local

    get group ::

        requests.post('http://127.0.0.1:5012/proxy/get_group', json={'event_id': '2', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"event_id": "2", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/get_group

    get groups ::

        requests.post('http://127.0.0.1:5012/proxy/get_groups', json={'user_id': '682109031847376', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/get_groups

    notifications manager ::

        requests.post('http://127.0.0.1:5012/proxy/notifications_manager', json={'type': 'reminder', 'event_id': '2', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"type": "reminder", "event_id": "2", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/notifications_manager

    invite friends ::

        requests.post('http://127.0.0.1:5012/proxy/invite_friends', json={'user_id': '682109031847376', 'event_id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "event_id": "7", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/invite_friends

    leave group ::

        requests.post('http://127.0.0.1:5012/proxy/leave_group', json={'user_id': '682109031847376', 'event_id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "event_id": "7", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/leave_group

    delete group ::

        requests.post('http://127.0.0.1:5012/proxy/delete_group', json={'user_id': '682109031847376', 'event_id': '7', 'access_token': 'helloworld'})

    ::

        curl -H "Content-Type: application/json" -X POST -d '{"user_id": "682109031847376", "event_id": "7", "access_token": "helloworld"}' http://127.0.0.1:5012/proxy/delete_group

    authentication app (GET and POST)::

            requests.post('http://127.0.0.1:5012/proxy/authentication_app', json={'username': 'service_name'}

        ::

            curl -H "Content-Type: application/json" -X POST -d '{"username": "service_name"}' http://127.0.0.1:5012/proxy/authentication_app

        ::
            requests.get('http://127.0.0.1:5012/proxy/authentication_app', auth=('service_name', 'digest(nonce)+digest(password)'))

        ::

            curl -u service_name:digest(nonce)+digest(password) http://127.0.0.1:5012/proxy/authentication_app



