from flask import Flask, request
from flask_restful import Resource, Api, reqparse
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import coloredlogs
import logging
import jwt
import os

logger = logging.getLogger('AuthenticationServer Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)

coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('AuthenticationServer'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)


app = Flask('AuthenticationServer')
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///authentication.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
api = Api(app)
GET_METHODS = ['validate', 'get_token']


def require_admin(f):
    """Do not add a client without admin permission"""
    def wrapper(*args, **kwargs):
        logger.info('Validating admin')
        credentials = request.authorization
        for field in ('username', 'password'):
                if field not in list(credentials.keys()):
                    return {'msg' :'{} cannot be blank'.format(field),
                            'ack': 'false'}, 400
        logger.info(credentials)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(credentials['password'].encode('utf-8'))
        password = digest.finalize().hex()
        admin = Admins.query.filter_by(admin=credentials['username'], password=password).first()
        if admin:
            return f(*args, **kwargs)
        return {'ack': 'false',
                'msg': 'Operation denied.'}, 403
    return wrapper


def check_challenger(username, nonce, nonce_response):
    # SHA256
    client = Client.query.filter_by(username=username).first()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(nonce.encode('utf-8'))
    nonce_digest = digest.finalize().hex()
    return True if nonce_response == (nonce_digest + client.password) else False


class Client(db.Model):
    username = db.Column(db.String(40), nullable=False, primary_key=True)
    password = db.Column(db.String(40), nullable=False)
    jwt_bearer = db.Column(db.String(400), unique=True, nullable=True)


class Admins(db.Model):
    admin = db.Column(db.String(40), nullable=False, primary_key=True)
    password = db.Column(db.String(40), nullable=False)


def validate_requester(req):
    headers = dict(request.headers.items())
    if 'Authorization' in list(headers.keys()):
        if 'Bearer' in headers['Authorization']:
            jwt_requester = headers['Authorization'].replace('Bearer ', '')
            client = Client.query.filter_by(jwt_bearer=jwt_requester).first()
            if client:
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(client.username.encode('utf-8'))
                audience = digest.finalize().hex()

                decoded = jwt.decode(client.jwt_bearer, app.secret_key, algorithm='HS256', audience=audience)

                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(app.name.encode('utf-8'))
                digest_appname = digest.finalize().hex()
                if decoded['iss'] == digest_appname:
                    return True
    return False


# JWT Provider
class Authentication(Resource):
    @staticmethod
    def get(method):
        if method not in GET_METHODS:
            return {'Error': 'Method Not Allowed'}, 405
        if method == 'get_token':
            data = request.authorization
            for field in ('username', 'password'):
                if field not in list(data.keys()):
                    return {'msg' :'{} cannot be blank'.format(field),
                            'ack': 'false'}, 400
            if data['username'] in list(PENDING_AUTHENTICATION.keys()):
                logger.info('Request nonce and password')
                # nonce ram, do not save it on database
                if check_challenger(username=data['username'], nonce=PENDING_AUTHENTICATION[data['username']],
                                    nonce_response=data['password']):
                    client = Client.query.filter_by(username=data['username']).first()

                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(app.name.encode('utf-8'))
                    digest_appname = digest.finalize().hex()
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(client.username.encode('utf-8'))
                    audience = digest.finalize().hex()

                    encoded_jwt = jwt.encode(dict(iss=digest_appname, iat=datetime.utcnow(), aud=audience),
                                             app.secret_key, algorithm='HS256')
                    logger.info('Sending jwt')
                    client.jwt_bearer = encoded_jwt.decode('utf-8')
                    db.session.add(client)
                    db.session.commit()
                    # clear nonce
                    del PENDING_AUTHENTICATION[data['username']]
                    return {'jwt-bearer': encoded_jwt.decode('utf-8')}, 200
                logger.warning('Invalid nonce and password, aborting jwt process.')
                return {'error': 'Invalid credentials'}, 401
        
        if method == 'validate':
            if validate_requester(request):
                parser = reqparse.RequestParser()
                parser.add_argument('jwt', type=str, location='args', required=True, help='JWT cannot be blank')
                args = parser.parse_args(strict=True)

                client = Client.query.filter_by(jwt_bearer=args['jwt']).first()
                if client:
                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(client.username.encode('utf-8'))
                    audience = digest.finalize().hex()

                    decoded = jwt.decode(client.jwt_bearer, app.secret_key, algorithm='HS256', audience=audience)

                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(app.name.encode('utf-8'))
                    digest_appname = digest.finalize().hex()
                    if decoded['iss'] == digest_appname:
                        return {'ack': 'true',
                                'audience': audience}, 200
                return {'ack': 'false'}, 400
            else:
                return {'ack': 'false'}, 403

    @staticmethod
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, location='json', required=True, help='Username cannot be blank')
        args = parser.parse_args(strict=True)
        logger.info('Authentication for {} started...'.format(args['username']))
        nonce = os.urandom(12).hex()
        client = Client.query.filter_by(username=args['username']).first()
        if client:
            logger.info('Request nonce and password')
            PENDING_AUTHENTICATION[args['username']] = nonce
            return {'nonce': nonce}, 200
        else:
            return {'ack': 'false',
                    'msg': 'Client does not exist'}, 200
        logger.warning('Username: {}, does not exist.'.format(args['username']))

class AuthenticationManagment(Resource):
    @staticmethod
    @require_admin
    def post():
        parser = reqparse.RequestParser()
        parser.add_argument('client_name', type=str, location='json', required=True, help='client_name cannot be blank')
        parser.add_argument('client_password', type=str, location='json', required=True, help='client_password cannot be blank')
        args = parser.parse_args(strict=True)

        client = Client.query.filter_by(username=args['client_name']).first()
        if not client:
            client = Client(username=args['client_name'],
                            password=args['client_password'])
            db.session.add(client)
            db.session.commit()
            return {'ack': 'true'}, 200
        else:
            return {'ack': 'false',
                    'msg': 'Client already exists'}, 200


api.add_resource(Authentication, '/v1.0/authentication/<method>', '/v1.0/authentication/')
api.add_resource(AuthenticationManagment, '/v1.0/authenticationManagment/')

if __name__ == '__main__':
    db.init_app(app)
    db.create_all()
    # as server
    PENDING_AUTHENTICATION = {}
    app.run(debug=False, host='0.0.0.0', port=5013, threaded=True)
