from flask import Flask, request, abort
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from functools import wraps
from configurationParser import Configuration
import requests
import logging
import coloredlogs
import pymysql
import os

logger = logging.getLogger('LocationsManager Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

conn = pymysql.connect(host='172.18.0.9', port=3306, user='locationManager', passwd='location', db='location_db')

fileHandler = logging.FileHandler("{}.log".format('LocationsManager'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask('LocationsService')
app.logger.addHandler(ch)
app.secret_key = 'developement'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_locations.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
api = Api(app)
JWT = None

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


GET_METHODS = ['all_locations', 'most_voted', 'three_most_voted']
POST_METHODS = ['vote', 'add_location']


class EventLocation(Resource):
    @staticmethod
    @require_oauth('basic')
    def post(app_name):
        # Event ID get from EventManager by HTTP
        parser = reqparse.RequestParser()
        parser.add_argument('event_id', type=str, location='json', required=True, help='Event ID cannot be blank')
        parser.add_argument('timestamp', type=str, location='json', required=True, help='Timestamp cannot be blank')
        parser.add_argument('access_token', type=str, location='json', required=True)
        values = parser.parse_args(strict=True)

        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO EVENTLOCATIONS (ID,TIMESTAMP, APP) "
                           "VALUES (%s,%s, %s);", (values['event_id'], values['timestamp'], app_name))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return error_message('AddEvent', 'Internal error', 500)
        cursor.close()
        logger.info('HTTP POST AddEvent - successfully processed')
        return {'ack': 'true'}, 200
        
    @staticmethod
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('event_id', type=int, location='args', required=True, help='Event ID cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)

        cursor = conn.cursor()

        event_id = values["event_id"]

        cursor.execute("SELECT ID FROM EVENTLOCATIONS WHERE ID=%s AND APP=%s;", (event_id, app_name))
        exit_event = cursor.fetchall()

        if exit_event != ():
            try:
                cursor.execute("DELETE FROM VOTING WHERE EVENTID=%s AND APP=%s;", (event_id, app_name))
                cursor.execute("DELETE FROM EVENTLOCATIONS WHERE ID= %s AND APP=%s;", (event_id, app_name))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('DeleteEvent', 'Internal error', 500), 500
        else:
            logger.exception('Locations - DELETE - deleteLocation - Event does not exist')
            return error_message('deleteLocation', 'You do not have permission', 403), 403
        logger.info('HTTP DELETE Location - successfully processed')
        return {'ack': 'true'}, 200


class Voting(Resource):
    @staticmethod
    @require_oauth('basic')
    def get(method, app_name):
        if method not in GET_METHODS:
            return {'Error': 'Method Not Allowed'}, 405
        # returns {'locations': [(lat,long,votes,city),(lat_1,long_1,votes_1,city_1)]}
        if method == 'all_locations':
            parser = reqparse.RequestParser()
            parser.add_argument('event_id', type=int, location='args', required=True, help='Event id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            cursor.execute("SELECT LAT, LNG, VOTES, CITY FROM VOTING WHERE EVENTID=%s AND APP=%s ORDER BY PRIORITY;", (values['event_id'], app_name))
            locations = list(cursor.fetchall())
            cursor.close()
            logger.info('HTTP GET All Locations - successfully processed')
            return {"locations": locations}, 200
        if method == 'most_voted':
            parser = reqparse.RequestParser()
            parser.add_argument('event_id', type=int, location='args', required=True, help='Event id cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            cursor.execute("SELECT LAT, LNG, VOTES, PRIORITY FROM VOTING WHERE EVENTID = %s AND APP=%s ORDER BY VOTES DESC;",
                           (values['event_id'], app_name))
            results = list(cursor.fetchall())
            cursor.close()
            by_votes = [x for x in results if x[2] >= results[0][2]]
            # list with 4 elems(LAT, LNG, VOTES, PRIORITY)
            by_priority = list(max(by_votes, key=lambda elem: elem[3]))
            logger.info('HTTP GET Most Voted - successfully processed')
            return {'most_voted': by_priority}, 200
        if method == 'three_most_voted':
            parser = reqparse.RequestParser()
            parser.add_argument('zone', type=str, location='args', required=False, help='Zone cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)

            cursor = conn.cursor()
            cursor.execute("SELECT ID, TIMESTAMP FROM EVENTLOCATIONS WHERE APP=%s;", (app_name,))
            result = list(cursor.fetchall())
            locations = {}
            if result:
                for element in result:
                    print(element)
                    if values['zone'] is None:
                        cursor.execute("SELECT LAT, LNG, VOTES, PRIORITY FROM VOTING WHERE EVENTID = %s AND APP=%s ORDER BY "
                                       "VOTES;", (element[0], app_name))
                    else:
                        cursor.execute(
                            "SELECT LAT, LNG, VOTES, PRIORITY FROM VOTING WHERE EVENTID = %s AND CITY = %s AND APP=%s ORDER BY "
                            "VOTES;", (element[0], values['zone'], app_name))
                    tmp = list(cursor.fetchall())
                    print(tmp)
                    # get all the locations with same votes number
                    by_votes = [x for x in tmp if x[2] >= tmp[0][2]]

                    # decision taken, get 1 location
                    if datetime.utcnow().timestamp() >= element[1]:
                        one = sorted(by_votes, key=lambda elem: elem[3], reverse=True)[:1]
                        one = [x[:3] for x in one]
                        # {'event_id': [(lat,long,votes)]}
                        locations[element[0]] = one
                    else:
                        three = sorted(by_votes, key=lambda elem: elem[3], reverse=True)[:3]
                        three = [x[:3] for x in three]
                        locations[element[0]] = three
                cursor.close()
                logger.info('HTTP GET Three Most Voted - successfully processed')
                return locations, 200
            cursor.close()
            logger.exception('HTTP - POST - Three Most Voted - There are no events')
            return error_message('ThreeMostVoted', 'There are no events', 401)

    @staticmethod
    @require_oauth('basic')
    def post(method, app_name):
        if method not in POST_METHODS:
            return {'Error': 'Method Not Allowed'}, 405
        if method == 'add_location':
            parser = reqparse.RequestParser()
            parser.add_argument('event_id', type=int, location='json', required=True, help='Event ID cannot be blank')
            parser.add_argument('lat', type=str, location='json', required=True, help='Latitude cannot be blank')
            parser.add_argument('long', type=str, location='json', required=True, help='Longitude cannot be blank')
            parser.add_argument('city', type=str, location='json', required=True, help='City cannot be blank')
            parser.add_argument('priority', type=int, location='json', required=True, help='Priority cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO VOTING(LAT, LNG, PRIORITY, VOTES, EVENTID, CITY, APP) "
                               "VALUES (%s, %s, %s, %s, %s, %s, %s);", (values['lat'], values['long'],
                                                                    values['priority'], 0, values['event_id'],
                                                                    values['city'], app_name))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('AddLocation', 'Internal error', 500)
            cursor.close()
            logger.info('HTTP POST AddLocation - successfully processed')
            return {'ack': 'true'}, 200

        if method == 'vote':
            parser = reqparse.RequestParser()
            parser.add_argument('event_id', type=int, location='json', required=True, help='Event ID cannot be blank')
            parser.add_argument('lat', type=str, location='json', required=True, help='Latitude cannot be blank')
            parser.add_argument('long', type=str, location='json', required=True, help='Longitude cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)

            cursor = conn.cursor()
            cursor.execute("SELECT TIMESTAMP FROM EVENTLOCATIONS WHERE ID = %s AND APP=%s;", (values['event_id'], app_name))
            timestamp = cursor.fetchone()
            if timestamp is not None:
                print(datetime.utcnow().timestamp())
                if datetime.utcnow().timestamp() < timestamp[0]:
                    cursor.execute("SELECT VOTES FROM VOTING WHERE LAT=%s AND LNG=%s AND EVENTID=%s AND APP=%s;",
                                   (values['lat'], values['long'], values['event_id'], app_name))
                    votes = cursor.fetchone()
                    if votes is not None:
                        try:
                            cursor.execute(
                                "UPDATE VOTING SET VOTES=%s WHERE LAT=%s AND LNG=%s AND EVENTID=%s AND APP=%s;",
                                (votes[0] + 1, values['lat'], values['long'], values['event_id'], app_name))
                            conn.commit()
                        except (pymysql.Error, Exception) as error:
                            conn.rollback()
                            cursor.close()
                            logger.exception(error)
                            return error_message('Vote', 'Internal error', 500)
                        cursor.close()
                        logger.info('HTTP POST Vote - successfully processed')
                        return {'ack': 'true'}, 200
                    cursor.close()
                    logger.exception('Events - POST - Vote - Invalid event and location')
                    return error_message('Vote', 'Invalid event and location', 403)
                logger.exception('Events - POST - Vote - Decision taken')
                return error_message('Vote', 'Decision taken', 400)


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
    

api.add_resource(EventLocation, '/locationManager/v1.1/Event_location/')
api.add_resource(Voting, '/locationManager/v1.1/voting/', '/locationManager/v1.1/voting/<method>')
api.add_resource(Internal, '/locationManager/v1.1/internal/')
api.add_resource(Authorization, '/locationManager/v1.1/authorization/')
api.add_resource(AuthorizationManagment, '/locationManager/v1.1/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    db.create_all()
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    user = User.query.filter_by(service_name='LocationsService').first()
    if not user:
        user = User(id=1, service_name='LocationsService')
        db.session.add(user)
        db.session.commit()
    app.run(port=5005, host='0.0.0.0', debug=False, threaded=True)
