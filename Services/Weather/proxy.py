from flask import Flask, request, abort
from flask_restful import Resource, Api, reqparse
from datetime import datetime,timedelta
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from flask_apscheduler import APScheduler
from configurationParser import Configuration
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.client import OAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from apscheduler.schedulers.background import BackgroundScheduler
from secrets import token_bytes
from functools import wraps
import requests
import logging
import coloredlogs
import pymysql
import os

logger = logging.getLogger('WeatherProxy Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('WeatherProxy'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

error_message = lambda x, y, z: {'error': x, 'msg': y, 'code': z}
DEGREE_DIFFERENCE = 5

# DB auto generate
class Config(object):
    SCHEDULER_JOBSTORES = {
        'default': SQLAlchemyJobStore(url='sqlite:///jobs.db')
    }

    SCHEDULER_API_ENABLED = True
    SCHEDULER_TIMEZONE = 'Europe/London'
    

app = Flask('WeatherProxy')
app.logger.addHandler(ch)
app.secret_key = 'developement'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_weatherproxy.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
# as client
oauth_client = OAuth(app)
api = Api(app)
app.config.from_object(Config())

conn = pymysql.connect(host='172.18.0.15', port=3306, user='alarmManager', passwd='alarm', db='alarm_weather_db')
GET_METHODS = ['AlarmW_ID','AlarmW']
JWT = None
CREDENTIALS= {}

def build_remote_app(consumer_key, consumer_secret, request_token_params, service):
    remote = oauth_client.remote_app(
        service,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        request_token_params=request_token_params,
        base_url=SERVICES['WEATHERPROXY']['HOST'],
        request_token_url=None,
        access_token_url=SERVICES[service]['AUTHORIZATION'],
        authorize_url=SERVICES[service]['AUTHORIZATION'])
    return remote


def check_authorization(*services):
    """Check authorization for a access to a resource."""
    def wrapper(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            logger.info('Decorator check authorization')
            for service in services:
                logger.info(services)
                logger.info(STATE)
                if STATE[service] is not None:
                    continue
                else:
                    logger.info('Start authorization process')
                    logger.info(service)
                    logger.info(CREDENTIALS[service]['client_id'])
                    remote = build_remote_app(CREDENTIALS[service]['client_id'],
                                              CREDENTIALS[service]['client_secret'],
                                              {'scope': SERVICES[service]['SCOPES'], 'jwt-bearer': JWT}, service)
                    PENDING_AUTHORIZATION[service] = remote
                    logger.info('Sending authorization request for service {}'.format(service))
                    return remote.authorize(callback=SERVICES[service]['CALLBACK'])
            return f(*args, **kwargs)
        return decorated
    return wrapper

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
            if request.method == 'GET':
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


class authorizationCallback(Resource):
    @staticmethod
    def get():
        global STATE
        logger.info('Authorization Callback')
        key = list(PENDING_AUTHORIZATION.keys())[0]
        resp = PENDING_AUTHORIZATION[key].authorized_response()
        STATE[resp['service']] = (PENDING_AUTHORIZATION[key], resp['access_token'])
        logger.info('Getting access key for {}'.format(resp['service']))
        del PENDING_AUTHORIZATION[key]
        # REMOVE THEN
        logger.info('{}'.format(resp['access_token']))
        return 'ack'


class Proxy(Resource):
    @staticmethod
    @check_authorization('UndergroundWeather', 'OpenWeather')
    @require_oauth('basic')
    def post(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('lat', type=str, location='json',required=True, help='Latitude cannot be blank')
        parser.add_argument('long', type=str, location='json', required=True, help='Longitude cannot be blank')
        parser.add_argument('day', type=str, location='json', required=True, help='Day cannot be blank')
        parser.add_argument('hour', type=str, location='json', required=True, help='Hour cannot be blank')
        data = parser.parse_args()

        try:
            r_und = requests.post(SERVICES['UndergroundWeather']['POST'], json={
                'day': data['day'],
                'hour': data['hour'],
                'lat': data['lat'],
                'long': data['long'],
                'access_token':STATE['UndergroundWeather'][1]
            }).json()
        except requests.exceptions.RequestException as e:
            logger.exception(e)
            return error_message('Proxy Weather', 'Internal error', 500)

        try:
            r_opw = requests.post(SERVICES['OpenWeather']['POST'], json={
                'day': data['day'],
                'hour': data['hour'],
                'lat': data['lat'],
                'long': data['long'],
                'access_token':STATE['OpenWeather'][1]
            }).json()
        except requests.exceptions.RequestException as e:
            logger.exception(e)
            return error_message('Proxy Weather', 'Internal error', 500)

        logger.info(r_und)
        logger.info(r_opw)
        logger.info(r_opw['temp'])
        logger.info(r_und['temp'])
        if r_und != [] and r_opw != []:
            logger.info('HTTP GET Weather - successfully processed')
            final_temp = (float(r_opw['temp'])+float(r_und['temp']))/2
            logger.info(final_temp)
            return {'hour': data['hour'], 'temp': final_temp , 'condition': r_und['condition'],
                'day': data['day']}
        elif r_und != []:
            logger.info('HTTP GET Weather - successfully processed')
            return {'hour': data['hour'], 'temp': r_und['temp'], 'condition': r_und['condition'], 'day': data['day']}
        elif r_opw != []:
            logger.info('HTTP GET Weather - successfully processed')
            return {'hour': data['hour'], 'temp': r_opw['temp'], 'condition': r_opw['condition'], 'day': data['day']}
        else:
            logger.exception('Weather - No forecast available')
            return {'error': 'No forecast available'}


def job_builder(id, func, args,trigger='interval', seconds=10):
    job = {'id': id,
           'func': func,
           'args': args,
           'trigger': trigger,
           'seconds': seconds}
    return job


class AlarmWeather(Resource):
    @staticmethod
    @require_oauth('basic')
    def post(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('datetime', type=str, location='json', required=True, help='Datetime cannot be blank')
        parser.add_argument('lat', type=str, location='json', required=True, help='Latitude cannot be blank')
        parser.add_argument('long', type=str, location='json', required=True, help='Latitude cannot be blank')
        parser.add_argument('id', type=str, location='json', required=True, help='Event ID cannot be blank')
        args = parser.parse_args(strict=True)

        datetime_object = datetime.strptime(args['datetime'], '%H:%M %d/%m/%Y')

        try:
            temp = requests.post(SERVICES['WEATHERPROXY']['GET'], json={'day': str(datetime_object.day),
                                                                      'hour': str(datetime_object.hour),
                                                                      'lat': args['lat'],
                                                                      'long': args['long']}).json()['temp']

        except KeyError:
            logger.warning('Key error - temp')
        else:
            cursor = conn.cursor()
            try:
                # set original temperature for the event id
                cursor.execute("INSERT INTO weather(EVENT_ID, DATETIME,TEMP_1, APP)"
                               "VALUES (%s,%s,%s);", (args['id'], args['datetime'], temp, app_name))
                element_id = cursor.lastrowid
                print(element_id)
                job_weather = str(element_id) + '_job_weather'
                cursor.execute("UPDATE weather SET JOB_WEATHER = %s WHERE ID = %s;", (1, element_id))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
            else:
                # runs once every hour to check temperature changes
                scheduler.add_job(
                    **job_builder(id=job_weather, func=weather_change, args=(datetime_object, args['lat'],
                                                                             args['long'], element_id), seconds=3600))

    @staticmethod
    @require_oauth('basic')
    def get(method, app_name):
        if method not in GET_METHODS:
            return {'Error': 'Method Not Allowed'}, 405
        if method == 'AlarmW_ID':
            parser = reqparse.RequestParser()
            parser.add_argument('event_id', type=int, location='json', required=True,
                                help='Event id cannot be blank')
            values = parser.parse_args(strict=True)

            try:
                cursor = conn.cursor()
                cursor.execute("SELECT TEMP_1, TEMP_2, JOB_WEATHER FROM weather WHERE EVENT_ID=%s AND APP=%s;", (values["event_id"], app_name))
            except pymysql.Error:
                cursor.close()
                logger.exception('AlarmWeather - Get')
                return error_message('AlarmWeather', 'Internal error', 500)
            results = cursor.fetchone()
            cursor.close()
            logger.info('HTTP GET Locations - successfully processed')
            return {"Alarm_Weather": results}, 200

        if method == 'AlarmW':
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM weather WHERE APP=%s;", (app_name,))
            except pymysql.Error:
                cursor.close()
                logger.exception('AlarmWeather - Get')
                return error_message('AlarmWeather', 'Internal error', 500)
            results = cursor.fetchall()
            cursor.close()
            logger.info('HTTP GET Locations - successfully processed')
            return {"Alarm_Weather": results}, 200


def weather_change(datetime_object, lat, long, row_id):
    # check new temperatures
    try:
        event_temperature = requests.post(SERVICES['WEATHERPROXY']['GET'], json={'day': str(datetime_object.day),
                                                                               'hour': str(datetime_object.hour),
                                                                               'lat': lat,
                                                                               'long': long
                                                                               }).json()['temp']
    except KeyError:
        logger.warning('Weather - Key error - temp')
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE weather SET JOB_WEATHER = %s WHERE ID = %s;", (0, row_id))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return error_message('weather_change', 'Internal error', 500)
        #cursor.close()

        scheduler.delete_job(id=str(row_id) + '_job_weather')
        logger.info('Weather - Job {} ended at {}'.format(str(row_id) + '_job_weather',
                                                          datetime.utcnow().strftime('%B %d %Y - %H:%M:%S')))
        return

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT TEMP_1,TEMP_2, EVENT_ID FROM weather WHERE ID = %s;", row_id)
    except (pymysql.Error, Exception) as error:
        cursor.close()
        logger.exception(error)
        return error_message('weather_change', 'Internal error', 500)

    c = cursor.fetchone()
    foriginal, fprevista, event_id = c

    temp_forecast = float(foriginal)

    differenceM = abs(temp_forecast - float(event_temperature))

    if differenceM >= DEGREE_DIFFERENCE:
        cursor = conn.cursor()
        if fprevista is None:
            try:
                cursor.execute("UPDATE weather SET TEMP_2 = %s WHERE ID = %s;", (event_temperature, row_id))
                #logger.info("Temperature of event "+str(event_id)+" change to: "+str(event_temperature))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('weather_change', 'Internal error', 500)

        logger.info(fprevista is not None)

        if fprevista is not None:
            if event_temperature > fprevista:
                cursor = conn.cursor()
                try:
                    cursor.execute("UPDATE weather SET TEMP_1 = %s, TEMP_2 = %s "
                                   "WHERE ID = %s;", (fprevista, event_temperature, row_id))

                    #logger.info("Temperature of event " + str(event_id) + " change to: " + str(event_temperature))
                    conn.commit()

                except (pymysql.Error, Exception) as error:
                    conn.rollback()
                    cursor.close()
                    logger.exception(error)
                    return error_message('weather_change', 'Internal error', 500)

    if differenceM <= - DEGREE_DIFFERENCE:
        cursor = conn.cursor()
        if fprevista is None:
            try:
                cursor.execute("UPDATE weather SET TEMP_2 = %s WHERE ID = %s;", (event_temperature,row_id))
                #logger.info("Temperature of event "+str(event_id)+" change to: "+str(event_temperature))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
        cursor.close()

        if fprevista is not None:
            if event_temperature > fprevista:
                try:
                    cursor.execute("UPDATE weather SET TEMP_1 = %s AND TEMP_2 = %s "
                                   "WHERE ID = %s;", (fprevista,event_temperature, row_id))
                    #logger.info("Temperature of event " + str(event_id) + " change to: " + str(event_temperature))
                    conn.commit()

                except (pymysql.Error, Exception) as error:
                    conn.rollback()
                    cursor.close()
                    logger.exception(error)
        cursor.close()

'''
    if datetime_object.hour  - datetime.utcnow().hour <= 10:
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE weather SET JOB_WEATHER = %s WHERE EVENT_ID = %s;", (0, event_id))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)

        scheduler.delete_job(id=str(row_id) + '_job_weather')
        logger.info('Weather - Job {} ended at {}'.format(str(row_id) + '_job_weather',
                                                          datetime.utcnow().strftime('%B %d %Y - %H:%M:%S')))

'''

class internal(Resource):
    @staticmethod
    def get():
        authentication()
        return get_credentials()

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

    
def get_credentials():
    reqs = []
    for service in AUTH_SERVICES:
        logger.info(service)
        event = requests.post(SERVICES[service]['GET_APP'],  
            json={'redirect_uri': SERVICES[service]['CALLBACK'], 'scopes': SERVICES[service]['SCOPES'], 'jwt-bearer': JWT})
        reqs.append(event.json())
        CREDENTIALS[service]=event.json()
    logger.info('Done: \n'.join('{}: {}'.format(*k) for k in enumerate(reqs)))
    return {'ack':'true'}


api.add_resource(Proxy, '/weatherproxy/v1.0/')
api.add_resource(AlarmWeather, '/weatherproxy/v1.0/alarmWeather/', '/weatherproxy/v1.0/alarmWeather/<method>')
api.add_resource(Authorization, '/weatherproxy/v1.0/authorization/')
api.add_resource(authorizationCallback, '/weatherproxy/v1.0/authorizationCallback/')
api.add_resource(internal, '/weatherproxy/v1.0/internal/')
api.add_resource(AuthorizationManagment, '/weatherproxy/v1.0/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    db.init_app(app)
    db.create_all()
    bc = BackgroundScheduler({'apscheduler.timezone': 'Europe/London'})
    scheduler = APScheduler(bc)
    scheduler.init_app(app)
    scheduler.start()
    user = User.query.filter_by(service_name='WeatherProxy').first()
    if not user:
        user = User(id=1, service_name='WeatherProxy')
        db.session.add(user)
        db.session.commit()
    PENDING_AUTHORIZATION = {}
    AUTH_SERVICES = [x for x in list(SERVICES.keys()) if x not in ('WEATHERPROXY', 'AUTHENTICATION')]
    logger.info('Services to get authorization: \n'.join('{}: {}'.format(*k) for k in enumerate(AUTH_SERVICES)))
    STATE = {k: None for k in AUTH_SERVICES}
    app.run(port=5008, host='0.0.0.0', threaded=True)