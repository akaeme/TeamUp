from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, abort
from configurationParser import Configuration
from flask_restful import Api, Resource, reqparse
import pymysql
import logging
import os
import requests
import coloredlogs

# Logger Configuration
logger = logging.getLogger('UserProfilingLogger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)


coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('UserProfilingLogger'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask("UserProfilingService")
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_facebook.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
api = Api(app)
JWT = None

conn = pymysql.connect(host='172.18.0.13', port=3306, user='userprofiling', passwd='profiling', db='userprofiling_db')
error_message = lambda x, y, z: {'error': x, 'msg': y, 'code': z}
POST_METHODS = ['create', 'update']
GET_METHODS = ['mobile', 'profile']


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


class UsersProfile(Resource):
    @staticmethod
    @require_oauth('basic')
    def post(method, app_name):
        print(method)
        if method not in POST_METHODS:
            return error_message('createProfile', 'Invalid method.', 403)

        if method == 'create':
            parser = reqparse.RequestParser()
            parser.add_argument('user_id', type=str, location='json', required=True, help='User ID cannot be blank')
            parser.add_argument('username', type=str, location='json', required=False, default="")
            parser.add_argument('mail', type=str, location='json', required=True, help='Mail cannot be blank')
            parser.add_argument('tlm', type=str, location='json', required=False, default="")
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()

            try:
                cursor.execute("SELECT UID FROM PROFILE WHERE APP=%s;", (app_name,))
                l = [str(x[0]) for x in cursor.fetchall()]
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('profile', 'Internal error', 500)

            if values["user_id"] not in l:
                try:
                    cursor.execute("INSERT INTO PROFILE(UID, USERNAME, MAIL, TLM, APP) VALUES"
                                   "(%s, %s, %s ,%s, %s);",
                                   (values["user_id"], values["username"], values["mail"], values["tlm"], app_name))
                    conn.commit()
                except (pymysql.Error, Exception) as error:
                    conn.rollback()
                    cursor.close()
                    logger.exception(error)
                    return error_message('createProfile', 'Internal error', 500)
            else:
                cursor.close()
                logger.error(' Profile with user id: {} already exists'.format(values['user_id']))
                return error_message('createProfile', 'Profile already exists.', 403)
            cursor.close()
            logger.info('HTTP POST Create - successfully processed')
            return {'ack': 'true'}, 200

        if method == 'update':
            parser = reqparse.RequestParser()
            parser.add_argument('user_id', type=str, location='json', required=True, help='User ID cannot be blank')
            parser.add_argument('username', type=str, location='json',required=False,  default="")
            parser.add_argument('mail', type=str, location='json', required=False,  default="")
            parser.add_argument('tlm', type=str, location='json', required=False,  default="")
            parser.add_argument('access_token', type=str, location='json', required=True)
            values = parser.parse_args(strict=True)
            user_id = values["user_id"]
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            try:
                cursor.execute("SELECT * FROM PROFILE WHERE UID=%s AND APP=%s;", (user_id, app_name))
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('profile', 'Internal error', 500)

            results = cursor.fetchone()

            if results is not None:
                del results["UID"]
                del values["user_id"]
                del values['access_token']

                values = {k.upper(): v for k, v in values.items() if v!=''}
                logging.info(values)
                results_ = {k: results[k] if values[k] is not None else None for k, v in values.items()}
                a = {x: values[x] for x in list(results_.keys()) if results_[x] not in list(values.values())}
               
                if bool(a):
                    my_query = "UPDATE PROFILE SET "
                    for k, v in a.items():
                        my_query += k + "=\"" + str(v) + "\","
                    my_query = my_query[:-1]

                    my_query += " WHERE UID={} AND APP=\"{}\";".format(user_id, app_name)
                    try:
                        cursor.execute(my_query)
                        conn.commit()
                        cursor.close()
                    except (pymysql.Error, Exception) as error:
                        conn.rollback()
                        cursor.close()
                        logger.exception(error)
                        return error_message('updateProfile', 'Internal error', 500)
                else:
                    logger.error('Profile with user id: {} is already up-to-date!'.format(user_id))
            else:
                logger.error('Profile with user id: {} does not exist'.format(values['user_id']))
                return error_message('updateProfile', 'Profile does not exist.', 403)
            cursor.close()
            logger.info('HTTP POST Update - successfully processed')
            return {'ack': 'true'}, 200

    @staticmethod
    @require_oauth('basic')
    def get(method, app_name):
        parser = reqparse.RequestParser()
        if method not in GET_METHODS:
            return {'Error': 'Method Not Allowed'}, 405

        if method == 'mobile':
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT UID, TLM FROM PROFILE WHERE APP = %s;", (app_name, ))
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('profile', 'Internal error', 500)

            user_profile = cursor.fetchall()
            cursor.close()

            mobile_numbers = []

            for l in user_profile:
                mobile_numbers.append({'user_id': l[0], 'phone': l[1]})
            logger.info('HTTP GET {} - successfully processed'.format(method))
            return {'mobile_numbers': mobile_numbers, 'ack': 'true'}, 200

        if method == 'profile':
            parser.add_argument('user_id', type=str, location='args', required=True, help='User ID cannot be blank')
            parser.add_argument('access_token', type=str, location='args', required=True)
            values = parser.parse_args(strict=True)
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT * FROM PROFILE WHERE UID=%s AND APP=%s;", (values["user_id"], app_name))
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('profile', 'Internal error', 500)

            user_profile = cursor.fetchone()
            print(user_profile)
            cursor.close()
            logger.info('HTTP GET {} - successfully processed'.format(method))
            return {'userProfile': user_profile, 'ack': 'true'}, 200

    @staticmethod
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('user_id', type=str, location='args', required=True, help='User ID cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        values = parser.parse_args(strict=True)
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT * FROM PROFILE WHERE UID=%s AND APP=%s;", (values["user_id"], app_name))
            user_profile = cursor.fetchone()
        except (pymysql.Error, Exception) as error:
            logger.exception(error)
            return error_message('profile', 'Internal error', 500)

        if user_profile is not None:
            try:
                cursor.execute("DELETE FROM PROFILE WHERE UID=%s AND APP=%s;", (values["user_id"], app_name))
                conn.commit()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('deleteProfile', 'Internal error', 500)
        else:
            cursor.close()
            logger.error(' Profile with user id: {} does not exist'.format(values['user_id']))
            return error_message('deleteProfile', 'Internal error.', 403)
        cursor.close()

        logger.info('HTTP DELETE - successfully processed')
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

    
api.add_resource(UsersProfile, '/userProfiling/v1.0/userProfile/<method>', '/userProfiling/v1.0/userProfile/')
api.add_resource(Internal, '/userProfiling/v1.0/internal/')
api.add_resource(Authorization, '/userProfiling/v1.0/authorization/')
api.add_resource(AuthorizationManagment, '/userProfiling/v1.0/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    db.create_all()
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    user = User.query.filter_by(service_name='UserProfilingService').first()
    if not user:
        user = User(id=1, service_name='UserProfilingService')
        db.session.add(user)
        db.session.commit()
    app.run(host='0.0.0.0', port=5007, debug=False, threaded=True)

