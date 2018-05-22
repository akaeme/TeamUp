Welcome to ``Authentication Manager`` Service's documentation!
==============================================================

Overview
--------
``Authentication Manager`` service is a Restful API that has a main objective: provide authentication and methods to confirm it.
This document describes the protocol used to send data to the API.

Communication is done over HTTP using POST methods. Request is formatted as JSON, and the content
type is ``application/json``.

Currently is in the ``version 1.0``.

Authentication Manager Requests
-------------------------------
Authentication requests can assume multiple types according to the desired operation.
Only ``GET/POST`` HTTP request methods are allowed.
The request data is appended on the body for ``POST`` requests and on arguments for ``GET``. The response body have JSON formatting.
Some methods are designed only to administrators of the service.
Every bad request is returned with a message indicating the wrong/missing fields and a explanatory message for each one.

Resources
---------
The are two main resources: one to provide authentication and one for handle the registered services. The first one is available to the world but only registered services will be successfully served with a JSON Web Token. The second one, is closed to admins os the service.

Authentication Resource
-----------------------
This resource provides a group of methods to handle all the operations related with authentication.
There are 3 methods: two ``GET`` and one ``POST``.
Following the communication with this service:

=================
POST Request
=================
The ``POST`` request allows to indicate to the service the authentication intent by providing a username.::

    http://127.0.0.1:5013/v1.0/authentication/

- Request Body
    The only fields is mandatory

    :class:`username`
        - The ``username`` that was used to regist a service. Type **str**.

- Response Body
    {'nonce': nonce}

=================
GET Request
=================
The ``GET`` request allows to get a JSON Web Token or validate it. To get it, the client must send a GET request with a authorization header containing the username and the nonce digest concatenated with the password digest.::

    http://127.0.0.1:5013/v1.0/authentication/get_token

-Request Header
	It must contain a HTTP Basic Auth with the username and digests concatenated. The digest function is ``SHA256``.

- Request Body
    There is no required fields.

- Response Body
    {'jwt-bearer': jwt}

The other ``GET`` request is related with the validation of a JSON Web Token::

	http://127.0.0.1:5013/v1.0/authentication/validate

-Request Header
	It must follow the Bearer Authentication, it is the token of the service requester. This token is also validated in order to confirm the authenticity of the requester::

		Authorization: Bearer <jwt>

- Request Body
    The only fields is mandatory

    :class:`jwt`
        - The ``jwt`` that must be validated. Type **str**.

- Response Body
    {'ack': 'true', 'audience': audience}

Authentication Managment Resource
---------------------------------
This resource provides a method to register a new service on this service in order to allow it to be authenticated on the further requests. Only admins of this service are allowed to operate over this resource::

	http://127.0.0.1:5013/v1.0/authenticationManagment/

-Request Header
	It must contain a HTTP Basic Auth with the username and the password of the admin.

- Request Body
    :class:`client_name`
        - The ``client_name`` is the service name, and it will be used on the process to get the authentication token. Type **str**.

     :class:`client_password`
        - The ``client_password`` is the desired password for the service, it also will be used on the authentication process. Type **str**.

- Response Body
    {'ack': 'true'}


Error Handling
--------------

Most common errors::

    +---------------+------------------------+
    | HTTP  Code    |      Description       |
    +---------------+------------------------+
    |     400       |  Bad Request           |
    +---------------+------------------------+
    |     401       |  Unauthorized          |
    +---------------+------------------------+
    |     403       |  Forbidden             |
    +---------------+------------------------+
    |     405       |  Method Not Allowed    |
    +---------------+------------------------+
    |     500       |  Internal Server Error |
    +---------------+------------------------+

Request Examples
----------------
Here we provide examples to each method, using `Requests <http://docs.python-requests.org/en/master/>`_ and
`cURL <https://curl.haxx.se/>`_.

- Authentication Resource
	- ``POST``
	    ::

	        requests.post('http://127.0.0.1:5013/v1.0/authentication/', json={'username': 'service_name'}

	    ::

	        curl -H "Content-Type: application/json" -X POST -d '{"username": "service_name"}' http://127.0.0.1:5013/v1.0/authentication/

	- ``GET``
		Get Token::

			requests.get('http://127.0.0.1:5013/v1.0/authentication/get_token', auth=('service_name', 'digest(nonce)+digest(password)'))

		::

			curl -u service_name:digest(nonce)+digest(password) http://127.0.0.1:5013/v1.0/authentication/get_token

		Validate Token::

			requests.get('http://127.0.0.1:5013/v1.0/authentication/validate', headers={'Authorization':'Bearer ' + jwt_requester}, params={'jwt': jwt})

		::

			curl -X GET -G http://127.0.0.1:5013/v1.0/authentication/validate -H "Authorization: Bearer jwt_requester" -d jwt=jwt

- Authentication Managment Resource
	- ``POST``
	    ::

	        requests.post('http://127.0.0.1:5013/v1.0/authenticationManagment/', json={'client_name': 'service_name', 'client_password': 'service_password'}, auth=('admin_username', 'admin_password'))

	    ::

	        curl -H "Content-Type: application/json" -X POST -d '{"client_name": "service_name", "client_password": "service_password"}' -u admin_username:admin_password http://127.0.0.1:5013/v1.0/authenticationManagment/



