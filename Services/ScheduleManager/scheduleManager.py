from flask import Flask, request, abort
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from functools import wraps
from configurationParser import Configuration
from datetime import datetime, timedelta
import pymysql
import logging
import coloredlogs
import jwt
import os
import time
import requests

logger = logging.getLogger('ScheduleManager Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)

coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")
fileHandler = logging.FileHandler("{}.log".format('ScheduleManager'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask('ScheduleManager')
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///jwt_oauth_eventsManager.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
api = Api(app)
JWT = None

conn = pymysql.connect(host='172.18.0.11', port=3306, user='scheduleManager', passwd='schedule', db='schedule_db')

error_message = lambda x, y, z: {'error': x, 'msg': y, 'code': z}

POST_METHODS = ['postSchedule', 'postRequest']
DELETE_METHODS = ['deleteSchedule', 'deleteAll']


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


class Schedule(Resource):
    # returns all schedules and votes for a request ID
    @staticmethod
    @require_oauth('basic')
    def get(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('request_id', type=int, location='args', required=True, help='Request ID cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT REQUEST_ID, TIMESTAMP, VOTES, PRIORITY FROM SCHEDULES WHERE REQUEST_ID=%s AND APP=%s;", (values["request_id"], app_name))
        except pymysql.Error:
            logger.exception('GetSchedule - Get')
            return error_message('GetSchedule', 'Internal error', 500)

        results = [x for x in cursor.fetchall()]
        logger.info(results)

        logger.info('HTTP GET Schedules - successfully processed')

        ret = []
        for a,b,c,d in results:
            #ret.append({'request_id': a, 'timestamp': b, 'votes': c, 'priority': d})
            ret.append([b,c,d])
        ret.sort(key=lambda x: int(x[2]), reverse=True)

        if len(ret) == 0:
            logger.info(ret)
            return ret, 200
        elif len(ret) == 1:
            logger.info([[ret[0][0],ret[0][1]]])
            return [[ret[0][0],ret[0][1]]], 200
        elif len(ret) == 2:
            logger.info([[ret[0][0],ret[0][1]], [ret[1][0],ret[1][1]]])
            return [[ret[0][0],ret[0][1]], [ret[1][0],ret[1][1]]], 200
        logger.info([[ret[0][0],ret[0][1]], [ret[1][0],ret[1][1]], [ret[2][0],ret[2][1]]])
        return [[ret[0][0],ret[0][1]], [ret[1][0],ret[1][1]], [ret[2][0],ret[2][1]]], 200


    # insert a new schedule for a request ID
    @staticmethod
    @require_oauth('basic')
    def post(method, app_name):
        if method not in POST_METHODS:
            return {'Error': 'Method Not Allowed'}, 405

        parser = reqparse.RequestParser()
        parser.add_argument('request_id', type=int, location='json', required=True, help='Request ID cannot be blank')
        parser.add_argument('timestamp', type=int, location='json', required=True, help='Timestamp cannot be blank')
        parser.add_argument('priority', type=int, location='json', required=False, help='Priority cannot be blank')
        parser.add_argument('access_token', type=str, location='json', required=True)
        values = parser.parse_args(strict=True)

        if method == 'postRequest':
            # check if already exists that requester
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT ID, TIMESTAMP FROM REQUEST WHERE ID=%s AND APP=%s;", (values['request_id'], app_name))
            except pymysql.Error:
                logger.exception('Schedule - Post')
                return error_message('PostRequest', 'Internal error', 500)

            if cursor.rowcount == 1:
                return error_message('PostRequest', 'Request already exists', 500)

            try:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO REQUEST (ID, TIMESTAMP, APP) VALUES (%s, %s, %s);",
                    (values['request_id'], values['timestamp'], app_name)
                )
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('PostRequest', 'Internal error', 500)

        if method == 'postSchedule':
            if values['priority'] is None:
                return error_message('PostSchedule', 'Priority cannot be blank', 500)
            # check if already exists that requester
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT ID, TIMESTAMP FROM REQUEST WHERE ID=%s AND APP=%s;", (values['request_id'], app_name))
            except pymysql.Error:
                logger.exception('Schedule - Post')
                return error_message('PostSchedule', 'Internal error', 500)

            if cursor.rowcount == 0:
                return error_message('PostSchedule', 'Request does not exist', 500)

            # check if timestamp given is before the decision timestamp
            if cursor.fetchone()[1] > values['timestamp']:
                return error_message('PostSchedule', 'Date given is before decision date', 500)

            # check if the request id and timestamp exist
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM SCHEDULES WHERE REQUEST_ID=%s AND TIMESTAMP=%s AND APP=%s;",
                               (values['request_id'], values['timestamp'], app_name))
            except pymysql.Error:
                logger.exception('Schedule - Post')
                return error_message('PostSchedule', 'Internal error', 500)

            if cursor.rowcount == 0:
                try:
                    cursor = conn.cursor()
                    cursor.execute(
                        "INSERT INTO SCHEDULES (REQUEST_ID, TIMESTAMP, VOTES, PRIORITY, APP) VALUES (%s, %s, %s, %s, %s);",
                        (values['request_id'], values['timestamp'], 0, values['priority'], app_name)
                    )
                    conn.commit()

                except (pymysql.Error, Exception) as error:
                    conn.rollback()
                    cursor.close()
                    logger.exception(error)
                    return error_message('PostSchedule', 'Internal error', 500)

            else:
                return error_message('PostSchedule', 'Schedule already exists' , 500)

        logger.info('HTTP POST Schedule - successfully processed')
        return {'ack': 'true'}, 200

    # delete a schedule for a request ID and timestamp or all schedules of an event
    @staticmethod
    @require_oauth('basic')
    def delete(method, app_name):
        if method not in DELETE_METHODS:
            return {'Error': 'Method Not Allowed'}, 405

        parser = reqparse.RequestParser()
        parser.add_argument('request_id', type=int, location='args', required=True, help='Request ID cannot be blank')
        parser.add_argument('timestamp', type=int, location='args', required=False, help='Timestamp')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)
        if method == 'deleteSchedule':
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM SCHEDULES WHERE REQUEST_ID=%s AND TIMESTAMP=%s AND APP=%s;",
                    (values['request_id'], values['timestamp'], app_name)
                )
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('DeleteSchedule', 'Internal error', 500)
            logger.info('HTTP DELETE Schedule - successfully processed')

        if method == 'deleteAll':
            # delete schedules
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM SCHEDULES WHERE REQUEST_ID=%s AND APP=%s;",
                    (values['request_id'], app_name)
                )
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('DeleteSchedule', 'Internal error', 500)
            # delete request id
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM REQUEST WHERE ID=%s AND APP=%s;",
                    (values['request_id'], app_name)
                )
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('DeleteSchedule', 'Internal error', 500)

            logger.info('HTTP DELETE Schedule - successfully processed')

        return {'ack': 'true'}, 200

class Voting(Resource):
    # returns schedule with more votes
    @staticmethod
    @require_oauth('basic')
    def get(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('request_id', type=int, location='args', required=True,
                            help='Request ID cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT REQUEST_ID, TIMESTAMP, VOTES, PRIORITY FROM SCHEDULES WHERE REQUEST_ID=%s AND APP=%s ORDER BY VOTES DESC;",
                           (values['request_id'], app_name))
        except pymysql.Error:
            logger.exception('Voting - Get')
            return error_message('GetVoting', 'Internal error', 500)

        results = [x for x in cursor.fetchall()]

        logger.info('HTTP GET Schedule Winner - successfully processed')

        ret = results[0]
        for a in results:
            if a[2] > ret[2]:       # votes
                ret = a
            elif a[2] == ret[2]:    # votes
                if a[3] > ret[3]:   # priority
                    ret = a

        return {"request_id": ret[0], "timestamp": ret[1], "votes": ret[2], "priority": ret[3]}, 200


    # vote for a schedule
    @staticmethod
    @require_oauth('basic')
    def post(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('request_id', type=int, location='json', required=True, help='Request ID cannot be blank')
        parser.add_argument('timestamp', type=int, location='json', required=True, help='Timestamp cannot be blank')
        parser.add_argument('access_token', type=str, location='json', required=True)
        values = parser.parse_args(strict=True)

        # check if the voting time has expired
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT ID, TIMESTAMP FROM REQUEST WHERE ID=%s AND APP=%s;", (values['request_id'], app_name))
        except pymysql.Error:
            logger.exception('Schedule - Post')
            return error_message('PostVoting', 'Internal error', 500)

        result = cursor.fetchall()
        if float(result[0][1]) < time.time():
            return error_message('PostVoting', 'Voting time expired', 500)

        # check if the request id and timestamp exist
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT TIMESTAMP, VOTES FROM SCHEDULES WHERE REQUEST_ID=%s AND TIMESTAMP=%s AND APP=%s;",
                           (values['request_id'], values['timestamp'], app_name))
        except pymysql.Error:
            logger.exception('Voting - Post')
            return error_message('PostVoting', 'Internal error', 500)

        if cursor.rowcount == 1:
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE SCHEDULES SET VOTES = VOTES +1 WHERE REQUEST_ID=%s AND TIMESTAMP=%s AND APP=%s;",
                    (values['request_id'], values['timestamp'], app_name)
                )
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('PostVoting', 'Internal error', 500)
        else:
            return error_message('PostVoting', 'Schedule does not exist', 500)

        logger.info('HTTP POST Voting - successfully processed')
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
    

api.add_resource(Schedule, '/scheduleManager/v1.0/schedule/', '/scheduleManager/v1.0/schedule/<method>')
api.add_resource(Voting, '/scheduleManager/v1.0/voting/')
api.add_resource(Internal, '/scheduleManager/v1.0/internal/')
api.add_resource(Authorization, '/scheduleManager/v1.0/authorization/')
api.add_resource(AuthorizationManagment, '/scheduleManager/v1.0/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    db.create_all()
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    user = User.query.filter_by(service_name='ScheduleManager').first()
    if not user:
        user = User(id=1, service_name='ScheduleManager')
        db.session.add(user)
        db.session.commit()
    app.run(port=5006, host='0.0.0.0', threaded=True)