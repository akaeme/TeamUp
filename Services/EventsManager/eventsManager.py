from flask import Flask, request, abort
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from datetime import datetime, timedelta
from configurationParser import Configuration
from functools import wraps
import pymysql
import logging
import coloredlogs
import os
import requests

logger = logging.getLogger('EventsManager Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)

coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('EventsManager'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask('EventsManagerService')
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_events_manager.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
api = Api(app)
JWT = None

conn = pymysql.connect(host='172.18.0.3', port=3306, user='eventsManager', passwd='events', db='events_db')

error_message = lambda x, y, z: {'error': x, 'msg': y, 'code': z}

def require_authentication(f):
    """Do not provide authorization until gets the authentication."""
    def wrapper(*args, **kwargs):
        logger.info('Validating jwt')
        if request.method == 'POST':
            jwt_bearer = request.get_json()['jwt-bearer']
            logger.info(jwt_bearer)
        else:
            jwt_bearer = request.args['jwt-bearer']
            logger.info(jwt_bearer)
        if jwt_bearer:
            validate = requests.get(SERVICES['AUTHENTICATION']['VALIDATE'], params={'jwt': jwt_bearer}, headers={'Authorization':'Bearer ' + JWT}).json()
            if validate['ack'] == 'true':
                kwargs['service_name'] = validate['audience']
                return f(*args, **kwargs)
        return {'ack': 'false',
                'msg': 'Authentication Requited.'}, 403
    return wrapper


def require_oauth(*scopes):
    """Protect resource with specified scopes."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            logger.info('Check authorization')
            if request.method == 'GET' or request.method == 'DELETE':
                access_token = request.args['access_token']
                logger.info(access_token)
            else:
                access_token = request.get_json()['access_token']
                logger.info(access_token)
            if access_token is not None:
                scopes_ = list(scopes)
                token_object = Token.query.join(Client, Token.client_id == Client.client_id)\
                    .add_columns(Token._scopes, Token.access_token, Client.service_name)\
                    .filter(Token.access_token == access_token).first()

                if token_object:
                    logger.info('Valid token')
                    if all(x in token_object._scopes for x in scopes_):
                        logger.info('Valid authorization')
                        kwargs['app_name'] = token_object.service_name
                        return f(*args, **kwargs)
            return abort(403)
        return decorated
    return wrapper


# Service
class User(db.Model):
    # service_id
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(40), unique=True)


class Client(db.Model):
    client_id = db.Column(db.String(100), primary_key=True)
    client_secret = db.Column(db.String(200), nullable=False)
    # it will have just 1 value
    user_id = db.Column(db.ForeignKey('user.id'), default='1')
    user = db.relationship('User')

    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)
    service_name = db.Column(db.String(200), unique=True)

    @property
    def client_type(self):
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []




class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # service_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    # Service
    user = db.relationship('User')

    client_id = db.Column(db.String(100), db.ForeignKey('client.client_id'),
                          nullable=False, )
    client = db.relationship('Client')

    code = db.Column(db.String(255), index=True, nullable=False)

    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)

    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(100), db.ForeignKey('client.client_id'), nullable=False)
    client = db.relationship('Client')
    # service_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Service
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(client_id=client_id).first()


@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    client = Client.query.filter_by(client_id=client_id).first()
    # Service object(id, name)
    user = User.query.get(client.user_id)
    if not user:
        logger.warning('User not found')
        exit()
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=user,
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id  # default
    )
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,  # default
    )
    db.session.add(tok)
    db.session.commit()
    return tok


# OAuth Provider
class Authorization(Resource):
    @staticmethod
    @require_authentication
    @oauth.authorize_handler
    def get(*args, **kwargs):
        logger.info('Authorize Handle')
        return True

    @staticmethod
    @oauth.token_handler
    def post():
        logger.info('Token Handle')
        return {'service': app.name}


class AuthorizationManagment(Resource):
    # create app
    @staticmethod
    @require_authentication
    def post(service_name):
        parser = reqparse.RequestParser()
        parser.add_argument('redirect_uri', type=str, location='json', required=True,
                            help='redirect_uri cannot be blank')
        parser.add_argument('scopes', type=str, location='json', required=True, help='scopes cannot be blank')
        parser.add_argument('jwt-bearer', type=str, location='json', required=True, help='JWT cannot be blank')
        args = parser.parse_args(strict=True)

        client = Client.query.filter_by(service_name=service_name).first()
        if client:
            return {'client_id': client.client_id,
                'client_secret': client.client_secret}, 200
                
        client_id = token_bytes(16)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(client_id.hex().encode('utf-8'))
        client_secret = digest.finalize().hex()
        client = Client(client_id=client_id.hex(),
                        client_secret=client_secret,
                        _redirect_uris=args['redirect_uri'],
                        _default_scopes=args['scopes'],
                        user_id=1,
                        service_name=service_name)
        db.session.add(client)
        db.session.commit()
        return {'client_id': client_id.hex(),
                'client_secret': client_secret}, 200


class Users(Resource):
    @staticmethod
    @require_oauth('basic')
    def get(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=str, location='args', required=True, help='User id cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT EVENTS_ID FROM PARTICIPANTS WHERE PARTICIPANT_ID=%s AND APP=%s;", (values["user_id"],app_name))
        except pymysql.Error:
            logger.exception('Users - Get')
            cursor.close()
            return error_message('Events', 'Internal error', 500), 500
        results = set([x[0] for x in cursor.fetchall()])
        cursor.close()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT ID, NAME, ACTIVITY, TYPE FROM EVENTS WHERE APP=%s;", (app_name,))
        except pymysql.Error:
            logger.exception('Users - Get ')
            cursor.close()
            return error_message('Events', 'Internal error', 500), 500
        events_info = list(cursor.fetchall())
        index = [x[0] for x in events_info]
        events = results.intersection(index)
        # private
        results_private = {}
        results_public = {}
        for x in events:
            for y in events_info:
                if y[0] == x:
                    if y[3] == 1:
                        results_private[x] = [y[1], y[2]]
                    else:
                        results_public[x] = [y[1], y[2]]
        results = {'private': results_private,
                   'public': results_public}
        cursor.close()
        logger.info('HTTP GET Users - successfully processed')
        return {'ack': 'true',
                "events": results}, 200

    @staticmethod
    @require_oauth('basic')
    def post(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('event_id', type=str, location='json', required=True, help='Event id cannot be blank')
        parser.add_argument('user_id', type=str, location='json', required=True, help='User id cannot be blank')
        parser.add_argument('access_token', type=str, location='json', required=True)
        values = parser.parse_args(strict=True)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO PARTICIPANTS(PARTICIPANT_ID, EVENTS_ID, APP) VALUES (%s, %s, %s);",
                           (values["user_id"], values["event_id"], app_name))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return error_message('AddUser', 'Internal error', 500), 500
        cursor.close()
        logger.info('HTTP POST Users - successfully processed')
        return {'ack': 'true'}, 200

    @staticmethod
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('event_id', type=str, location='args', required=True, help='Event id cannot be blank')
        parser.add_argument('user_id', type=str, location='args', required=True, help='User id cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)

        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM PARTICIPANTS WHERE EVENTS_ID=%s AND PARTICIPANT_ID=%s AND APP=%s;",
                           (values["event_id"], values["user_id"], app_name))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return error_message('RemoveUser', 'Internal error', 500), 500
        cursor.close()
        logger.info('HTTP DELETE Users - successfully processed')
        return {'ack': 'true'}, 200


POST_METHODS = ['create', 'update']
GET_METHODS = ['publicEvents', 'participants', 'eventName', 'publicByActivity', 'event_info']


class Events(Resource):
    @staticmethod
    @require_oauth('basic')
    def get(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('op_type', type=str, location='args', required=True, help='Operation type cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        op_type = parser.parse_args(strict=False)['op_type']
        logger.info(op_type)
        if op_type not in GET_METHODS:
            return {'Error': 'Method Not Allowed'}, 405

        if op_type == 'publicEvents':
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ID, NAME, ACTIVITY FROM EVENTS WHERE TYPE=%s AND APP=%s;", (0, app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('Events - Get - PublicEvents')
                return error_message('PublicEvents', 'Internal error', 500), 500
            results = [list(x) for x in cursor.fetchall()]
            cursor.close()
            logger.info('HTTP GET publicEvents - successfully processed')
            return {'ack': 'true',
                    "events": results}, 200

        if op_type == 'publicByActivity':
            parser = reqparse.RequestParser()
            parser.add_argument('op_type', type=str, location='args', required=True,
                                help='Operation type cannot be blank')
            parser.add_argument('activity', type=str, location='args', required=True,
                                help='Activity id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT ID, NAME, ACTIVITY  FROM EVENTS WHERE TYPE=%s AND ACTIVITY=%s AND APP=%s;", (0, values['activity'], app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('Events - Get - publicByActivity')
                return error_message('PublicByActivity', 'Internal error', 500), 500
            results = [list(x) for x in cursor.fetchall()]
            cursor.close()
            logger.info('HTTP GET publicByActivity - successfully processed')
            return {'ack': 'true',
                    "events": results}, 200

        if op_type == 'participants':
            parser = reqparse.RequestParser()
            parser.add_argument('op_type', type=str, location='args', required=True,
                                help='Operation type cannot be blank')
            parser.add_argument('event_id', type=str, location='args', required=True, help='Event id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT PARTICIPANT_ID FROM PARTICIPANTS WHERE EVENTS_ID=%s AND APP=%s;", (values["event_id"], app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('Events - Get - Participants')
                return error_message('Participants', 'Internal error', 500), 500
            results = [x[0] for x in cursor.fetchall()]
            cursor.close()
            logger.info('HTTP GET Participants - successfully processed')
            return {'ack': 'true',
                    "users": results}, 200

        if op_type == 'eventName':
            parser = reqparse.RequestParser()
            parser.add_argument('op_type', type=str, location='args', required=True,
                                help='Operation type cannot be blank')
            parser.add_argument('event_id', type=str, location='args', required=True, help='Event id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute("SELECT NAME FROM EVENTS WHERE ID=%s AND APP=%s;", (values["event_id"], app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('Events - Get - EventName')
                return error_message('EventName', 'Internal error', 500), 500
            res = cursor.fetchone() 
            cursor.close()
            if res is not None:
                name = res[0]
                
                return {'ack': 'true',
                        "eventName": name}, 200

        if op_type == 'event_info':
            parser = reqparse.RequestParser()
            parser.add_argument('op_type', type=str, location='args', required=True,
                                help='Operation type cannot be blank')
            parser.add_argument('event_id', type=str, location='args', required=True, help='Event id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT NAME, DESCRIPTION, ACTIVITY, ATMPPL, TYPE FROM EVENTS WHERE ID=%s AND APP=%s;",
                               (values["event_id"], app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('Events - Get - Event Info')
                return error_message('EventInfo', 'Internal error', 500), 500
            info = cursor.fetchone()
            cursor.close()
            return {'ack': 'true',
                    "info": info}, 200

    @staticmethod
    @require_oauth('basic')
    def post(method, app_name):
        if method not in POST_METHODS:
            return {'Error': 'Method Not Allowed'}, 405
        if method == 'create':
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str, location='json', required=True, help='Name cannot be blank')
            parser.add_argument('type', type=int, location='json', required=False, default=0)
            parser.add_argument('activity', type=str, location='json', required=True, help='Activity cannot be blank')
            parser.add_argument('maxppl', type=int, location='json', required=True,
                                help='Max number of people cannot be blank')
            parser.add_argument('minppl', type=int, location='json', required=False, default=0)
            parser.add_argument('owner', type=str, location='json', required=True, help='The event must have a owner')
            parser.add_argument('description', type=str, location='json', required=False, default='')
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO EVENTS(NAME, DESCRIPTION, ACTIVITY, TYPE, MAXPPL, MINPPL, OWNER, APP) VALUES (%s, %s, %s, %s, "
                    "%s, %s, %s, %s);",
                    (values["name"], values["description"], values["activity"], values["type"], values["maxppl"],
                     values["minppl"], values["owner"], app_name))
                event_id = cursor.lastrowid
                cursor.execute("INSERT INTO PARTICIPANTS(PARTICIPANT_ID, EVENTS_ID, APP) VALUES (%s, %s, %s);",
                               (values["owner"], event_id, app_name))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('CreateEvent', 'Internal error', 500), 500
            logger.info('HTTP POST create - successfully processed')
            return {'ack': 'true',
                    "events_id": event_id}, 200

        if method == 'update':
            parser = reqparse.RequestParser()
            parser.add_argument('user_id', type=str, location='json', required=True, help='User id cannot be blank')
            parser.add_argument('event_id', type=str, location='json', required=True, help='Event id cannot be blank')
            parser.add_argument('name', type=str, location='json')
            parser.add_argument('type', type=int, location='json')
            parser.add_argument('activity', type=str, location='json')
            parser.add_argument('maxppl', type=int, location='json')
            parser.add_argument('minppl', type=int, location='json')
            parser.add_argument('atmppl', type=int, location='json')
            parser.add_argument('description', type=str, location='json')
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)

            event_id = values["event_id"]
            user_id = values["user_id"]
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute("SELECT * FROM EVENTS WHERE ID=%s AND APP=%s;", (event_id, app_name))

            results = cursor.fetchone()

            if results is not None:
                cursor.execute("SELECT OWNER FROM EVENTS WHERE ID=%s AND APP=%s;", (event_id, app_name))
                owner_id = str(cursor.fetchone()["OWNER"])

                if user_id == owner_id:
                    del results["ID"]
                    del results["OWNER"]
                    del values["event_id"]
                    del values["user_id"]
                    del values['access_token']

                    values = {k.upper(): v for k, v in values.items()}

                    results_ = {k: results[k] if values[k] is not None else None for k, v in values.items()}

                    a = {x: values[x] for x in list(results_.keys()) if results_[x] not in list(values.values())}

                    my_query = "UPDATE EVENTS SET "
                    for k, v in a.items():
                        my_query += k + "=\"" + str(v) + "\","
                    my_query = my_query[:-1]

                    my_query += " WHERE ID={};".format(event_id)
                    try:
                        cursor.execute(my_query)
                        conn.commit()
                    except (pymysql.Error, Exception) as error:
                        conn.rollback()
                        cursor.close()
                        logger.exception(error)
                        return error_message('UpdateEvent', 'Internal error', 500), 500
                else:
                    logger.exception('Events - Post - updateEvent - permission denied')
                    return error_message('updateEvent', 'You do not have permission', 403), 403
            else:
                logger.exception('Events - Post - updateEvent - Event does not exist')
                return error_message('updateEvent', 'Event does not exist.', 403), 403
            logger.info('HTTP POST update - successfully processed')
            return {'ack': 'true'}, 200

    @staticmethod
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('event_id', type=str, location='args', required=True, help='Event id cannot be blank')
        parser.add_argument('user_id', type=str, location='args', required=True, help='User id cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)
        cursor = conn.cursor()

        event_id = values["event_id"]
        user_id = values["user_id"]

        cursor.execute("SELECT ID FROM EVENTS WHERE ID=%s AND APP=%s;", (event_id, app_name))
        exit_event = cursor.fetchall()

        if exit_event != ():
            cursor.execute("SELECT OWNER FROM EVENTS WHERE ID=%s AND APP=%s;", (event_id, app_name))
            owner_id = str(cursor.fetchone()[0])
            if user_id == owner_id:
                try:
                    cursor.execute("DELETE FROM PARTICIPANTS WHERE EVENTS_ID=%s AND APP=%s;", (event_id, app_name))
                    cursor.execute("DELETE FROM EVENTS WHERE ID= %s AND APP=%s;", (event_id, app_name))
                    conn.commit()
                except (pymysql.Error, Exception) as error:
                    conn.rollback()
                    cursor.close()
                    logger.exception(error)
                    return error_message('DeleteEvent', 'Internal error', 500), 500
            else:
                logger.exception('Events - DELETE - deleteEvent - Event does not exist')
                return error_message('deleteEvent', 'You do not have permission', 403), 403
        else:
            return error_message('deleteEvent', 'Event does not exist.', 403), 403
        logger.info('HTTP DELETE Event - successfully processed')
        return {'ack': 'true'}, 200


class Internal(Resource):
    @staticmethod
    def get():
        return authentication()

def authentication():
    global JWT
    req = requests.post(SERVICES['AUTHENTICATION']['POST'],
                        json={'username': SERVICES['AUTHENTICATION']['USERNAME']})
    nonce = req.json()['nonce']
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(nonce.encode('utf-8'))
    nonce_digest = digest.finalize().hex()

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(SERVICES['AUTHENTICATION']['PASSWORD'].encode('utf-8'))
    password_digest = digest.finalize().hex()

    req = requests.get(SERVICES['AUTHENTICATION']['GET'], auth=(SERVICES['AUTHENTICATION']['USERNAME'], nonce_digest + password_digest))
    JWT = req.json()['jwt-bearer']
    # REMOVE THEN
    logger.info('{}'.format(JWT))
    return {'ack':'true'}


api.add_resource(Events, '/eventsManager/v1.1/events/<method>', '/eventsManager/v1.1/events/')
api.add_resource(Users, '/eventsManager/v1.1/users/')
api.add_resource(Internal, '/eventsManager/v1.1/internal/')
api.add_resource(Authorization, '/eventsManager/v1.1/authorization/')
api.add_resource(AuthorizationManagment, '/eventsManager/v1.1/authorization_managment/')


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    db.create_all()
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    user = User.query.filter_by(service_name='EventsManager').first()
    if not user:
        user = User(id=1, service_name='EventsManager')
        db.session.add(user)
        db.session.commit()
    app.run(port=5002, host='0.0.0.0', debug=False, threaded=True)
