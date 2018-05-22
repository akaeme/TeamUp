from flask import Flask, request, abort
from flask_restful import Resource, Api, reqparse
from datetime import datetime, timedelta
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask_apscheduler import APScheduler
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.client import OAuth
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from functools import wraps
from configurationParser import Configuration
import pymysql
import requests
import coloredlogs
import logging
import os


logger = logging.getLogger('AlarmManager Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)


coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('AlarmManager'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

class Config(object):
    SCHEDULER_JOBSTORES = {
        'default': SQLAlchemyJobStore(url='sqlite:///jobs.db')
    }

    SCHEDULER_API_ENABLED = True
    SCHEDULER_TIMEZONE = 'Europe/London'


app = Flask('AlarmManager')
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_alarm_manager.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
# as client
oauth_client = OAuth(app)
api = Api(app)
app.config.from_object(Config())

conn = pymysql.connect(host='172.18.0.25', port=3306, user='alarmManager', passwd='alarm', db='alarm_db')
DEGREE_DIFFERENCE = 3

JWT = None
CREDENTIALS= {}

def build_remote_app(consumer_key, consumer_secret, request_token_params, service):
    remote = oauth_client.remote_app(
        service,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        request_token_params=request_token_params,
        base_url=SERVICES['ALARM_MANAGER']['HOST'],
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

def job_builder(id, func, args, run_date=None, trigger='interval', seconds=3600, type='weather'):
    if type == 'weather':     
        job = {'id': id,
               'func': func,
               'args': args,
               'trigger': trigger,
               'seconds': seconds}
    else:
        job = {'id': id,
               'func': func,
               'args': args,
               'trigger': 'date',
               'run_date': run_date
               }
    return job


class AlarmManager(Resource):
    @staticmethod
    @check_authorization('WeatherProxy', 'ScheduleManager')
    @require_oauth('basic')
    def post(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('datetime', type=str, location='json', required=True,
                            help='Datetime decision cannot be blank')
        parser.add_argument('id', type=str, location='json', required=True, help='Event ID cannot be blank')
        parser.add_argument('access_token', type=str, location='json', required=True)
        args = parser.parse_args(strict=True)

        # 18:30 23/01/2017
        datetime_object = datetime.strptime(args['datetime'], '%H:%M %d/%m/%Y')

        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO ALARM_MANAGER(DATETIME_DECISION, EVENT_ID, APP) "
                           "VALUES (%s, %s, %s);", (args['datetime'], args['id'], app_name))
            element_id = cursor.lastrowid
            job_decision = app_name + '_' + str(element_id) + '_job_decision'
            cursor.execute("UPDATE ALARM_MANAGER SET JOB_REMINDER = %s, JOB_WEATHER = %s, JOB_CLOSED_EVENT = %s, "
                           "JOB_DECISION= %s WHERE ID = %s AND APP= %s;", (0, 0, 0, 1, element_id, app_name))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return error_message('Create', 'Internal error', 500), 500
        else:
            cursor.close()
            # run once
            scheduler.add_job(
                **job_builder(id=job_decision, func=decision, args=(args['id'], element_id, app_name),
                              run_date=datetime_object, type='decision'))
            logger.info('Schedule for decision datetime added successfully.')
            return {'ack': 'true'}, 200

    @staticmethod
    @check_authorization('WeatherProxy', 'ScheduleManager')
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('id', type=str, location='args', required=True, help='Event ID cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        args = parser.parse_args(strict=True)

        cursor = conn.cursor()
        try:
            cursor.execute("SELECT ID, DATETIME FROM ALARM_MANAGER WHERE EVENT_ID = %s AND APP = %s;", (args['id'], app_name))
        except (pymysql.Error, Exception) as error:
            cursor.close()
            logger.exception(error)
        else:
            res = cursor.fetchone()
            cursor.close()
            logger.info(res)
            
            if res[1] is None:
                logger.info('The decision day has not yet come -  Deleted 1 job')
                scheduler.delete_job(id=app_name + '_' + str(res[0]) + '_job_decision')
            else:
                logger.info('The decision day has come -  Deleted 3 job')
                scheduler.delete_job(id=app_name + '_' + str(res[0]) + '_job_weather')
                scheduler.delete_job(id=app_name + '_' + str(res[0]) + '_job_reminder')
                scheduler.delete_job(id=app_name + '_' + str(res[0]) + '_job_closed_event') 
        
            cursor = conn.cursor()
            try:
                cursor.execute("DELETE FROM ALARM_MANAGER WHERE ID = %s AND APP = %s", (res[0], app_name))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                conn.rollback()
                cursor.close()
                logger.exception(error)
                return error_message('DELETE', 'Internal error', 500), 500
            else:
                cursor.close()
                logger.info('Deleted alarm successfully.')
                return {'ack': 'true'}, 200


def decision(event_id, row_id, app_name):
    app_server = requests.post(SERVICES['APPLICATION_SERVER']['POST'],
                               json={'type': 'decision',
                                     'event_id': event_id})
    if app_server.status_code == 200:
        logger.info('Request successfully sent.')
    else:
        logger.info('Request unsuccessfully sent.')
    req_schedule = requests.get(SERVICES['ScheduleManager']['MOST_VOTED'], params={'access_token': STATE['ScheduleManager'][1], 'request_id': event_id})
    if req_schedule.status_code == 200:
        timestamp = req_schedule.json()['timestamp']
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE ALARM_MANAGER SET DATETIME = %s, JOB_REMINDER = %s, JOB_WEATHER = %s, "
                           "JOB_CLOSED_EVENT = %s, JOB_DECISION = %s WHERE ID = %s AND APP = %s;", (datetime.fromtimestamp(timestamp), 
                            1, 1, 1, 0, row_id, app_name))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
        else:
            cursor.close()
            logger.info('Creating auxiliary jobs ')
            job_weather = app_name + '_' + str(row_id) + '_job_weather'
            job_reminder = app_name + '_' + str(row_id) + '_job_reminder'
            job_closed_event = app_name + '_' + str(row_id) + '_job_closed_event'
            # runs once every hour
            scheduler.add_job(
                **job_builder(id=job_weather, func=weather_change, args=(event_id, row_id, app_name)))
            # run once
            datetime_object = datetime.fromtimestamp(timestamp) - timedelta(hours=1)
            scheduler.add_job(
                **job_builder(id=job_reminder, func=reminder, args=(row_id, app_name),
                              run_date=datetime_object, type='reminder'))
            # run once
            scheduler.add_job(
                **job_builder(id=job_closed_event, func=closed_event, args=(row_id, app_name),
                              run_date=datetime.fromtimestamp(timestamp), type='closed_event'))


def weather_change(event_id, row_id, app_name):
    try:
        temp_1, temp_2, status = requests.get(SERVICES['WeatherProxy']['WEATHER_ALARM'],
                                              params={'access_token': STATE['WeatherProxy'][1], 'event_id': int(event_id)}).json()['Alarm_Weather']
    except KeyError:
        logger.warning('Internal Server Error - Weather Proxy')
    else:
        if status == 1:
            if temp_2 is not None:
                difference = temp_2 - temp_1
                change = False
                message = ''
                if difference >= DEGREE_DIFFERENCE:
                    change = True
                    message = ' - weather forecast decreased {}.'.format(str(abs(difference)))
                    logger.info('Weather - Job {} - Difference - (-5) Degrees'.format(row_id))
                if difference <= -DEGREE_DIFFERENCE:
                    change = True
                    message = ' - weather forecast increased {}.'.format(str(difference))
                    logger.info('Weather - Job {} - Difference - (+5) Degrees'.format(row_id))
                if change:
                    app_server = requests.post(SERVICES['APPLICATION_SERVER']['POST'],
                                               json={'type': 'weather', 'message': message, 'event_id': event_id})
                    if app_server.status_code == 200:
                        logger.info('Request successfully sent.')
                    else:
                        logger.info('Request unsuccessfully sent.')
                    scheduler.delete_job(id=app_name + '_' + str(row_id) + '_job_weather')
            else:
                logger.info('Weather keep None, no significantly changes')
        else:
            scheduler.delete_job(id=app_name + '_' + str(row_id) + '_job_weather')


def reminder(row_id, app_name):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT EVENT_ID FROM ALARM_MANAGER WHERE ID = %s AND APP = %s;", (row_id, app_name))
        event_id = cursor.fetchone()[0]
        cursor.execute("UPDATE ALARM_MANAGER SET JOB_REMINDER = %s WHERE ID = %s AND APP = %s;", (0, row_id, app_name))
        conn.commit()
    except (pymysql.Error, Exception) as error:
        conn.rollback()
        cursor.close()
        logger.exception(error)
    else:
        app_server = requests.post(SERVICES['APPLICATION_SERVER']['POST'], json={'type': 'reminder',
                                                                                          'event_id': event_id})
        if app_server.status_code == 200:
            logger.info('Request successfully sent.')
        else:
            logger.info('Request unsuccessfully sent.')
        logger.info('Reminder - Job {} ended at {}'.format(str(row_id) + '_job_reminder',
                                                           datetime.utcnow().strftime('%B %d %Y - %H:%M:%S')))


def closed_event(row_id, app_name):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT EVENT_ID FROM ALARM_MANAGER WHERE ID = %s AND APP = %s;", (row_id, app_name))
        event_id = cursor.fetchone()[0]
        cursor.execute("UPDATE ALARM_MANAGER SET JOB_CLOSED_EVENT = %s WHERE ID = %s AND APP = %s;", (0, row_id, app_name))
        conn.commit()
    except (pymysql.Error, Exception) as error:
        conn.rollback()
        cursor.close()
        logger.exception(error)
    else:
        app_server = requests.post(SERVICES['APPLICATION_SERVER']['POST'], json={'type': 'closed_event',
                                                                                          'event_id': event_id})
        if app_server.status_code == 200:
            logger.info('Request successfully sent.')
        else:
            logger.info('Request unsuccessfully sent.')
        scheduler.delete_job(id=str(row_id) + '_job_weather')
        logger.info('Closed Event - Job {} ended at {}'.format(str(row_id) + '_job_closed_event',
                                                               datetime.utcnow().strftime(
                                                                   '%B %d %Y - %H:%M:%S')))

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


api.add_resource(AlarmManager, '/alarmManager/v1.0/')
api.add_resource(Authorization, '/alarmManager/v1.0/authorization/')
api.add_resource(authorizationCallback, '/alarmManager/v1.0/authorizationCallback/')
api.add_resource(internal, '/alarmManager/v1.0/internal/')
api.add_resource(AuthorizationManagment, '/alarmManager/v1.0/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    PENDING_AUTHORIZATION = {}
    AUTH_SERVICES = [x for x in list(SERVICES.keys()) if x not in ('APPLICATION_SERVER', 'AUTHENTICATION', 'ALARM_MANAGER')]
    logger.info('Services to get authorization: \n'.join('{}: {}'.format(*k) for k in enumerate(AUTH_SERVICES)))
    STATE = {k: None for k in AUTH_SERVICES}
    db.init_app(app)
    db.create_all()
    bc = BackgroundScheduler({'apscheduler.timezone': 'Europe/London'})
    scheduler = APScheduler(bc)
    scheduler.init_app(app)
    scheduler.start()
    user = User.query.filter_by(service_name='AlarmManager').first()
    if not user:
        user = User(id=1, service_name='AlarmManager')
        db.session.add(user)
        db.session.commit()
    app.run(debug=False, host='0.0.0.0', port=5001)
