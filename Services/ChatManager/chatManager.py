from xml.etree import ElementTree
from configurationParser import Configuration
from flask import Flask, request, abort
from flask_restful import Api, Resource, reqparse
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from secrets import token_bytes
from datetime import datetime, timedelta
from functools import wraps
from xml.sax.saxutils import escape
from sleekxmpp.exceptions import IqError, IqTimeout
import pymysql
import logging
import requests
import coloredlogs
import os
import sleekxmpp


logger = logging.getLogger('ChatManager Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)

coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")


fileHandler = logging.FileHandler("{}.log".format('ChatManager'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask('ChatManager')
app.logger.addHandler(ch)
app.secret_key = 'development'
app.config.update({'SQLALCHEMY_DATABASE_URI': 'sqlite:///oauth_chat_manager.sqlite'})
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# as provider
oauth = OAuth2Provider(app)
api = Api(app)
JWT = None

MESSAGE_TYPE = ['sendInvite', 'createAndConfigureChatRoom', 'createUser', 'sendMessage', 'leaveChatRoom', 'setAffiliation']

conn = pymysql.connect(host='172.18.0.35', port=3306, user='chatManager', passwd='chatmanager', db='chat_db')

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


class Manager(sleekxmpp.ClientXMPP):
    def __init__(self, jid, password, nick):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.jid= jid
        self.nick=nick


    def register(self, user_JID, password):
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = user_JID
        resp['register']['password'] = password
        try:
            resp.send()
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            logging.error("Could not register account: %s" %
                          e.iq['error']['text'])
            return {'ack': 'true'}, 200

        except IqTimeout:
            logging.error("No response from server.")
            return {'ack': 'true'}, 417
        return {'ack': 'true'}, 200

    def setRole(self, room, nick, role):
        if role not in ('moderator', 'participant', 'visitor', 'none'):
            logging.error("Invalid role")
            return False
        query = ElementTree.Element('{http://jabber.org/protocol/muc#admin}query')
        item = ElementTree.Element('item', {'role': role, 'nick': nick})
        query.append(item)
        iq = self.makeIqSet(query)
        iq['to'] = room
        result = iq.send()
        if result is False or result['type'] != 'result':
            logging.error('Could not set Role')
            return False
        logging.error('Role assigned')
        return True

def enterAllMUC():
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM CHAT_ROOM;')
        rooms = cursor.fetchall()
    except (pymysql.Error, Exception) as error:
        cursor.close()
        logger.exception(error)
        return error_message('chatRoom', 'Internal error', 500)

    if rooms is not None:
        for room in rooms:
            xmpp.plugin['xep_0045'].joinMUC(str(room[0]), MANAGER['NICK'], wait=False)




class ChatManager(Resource):
    @staticmethod
    @require_oauth('basic')
    def post(method, app_name):

        if method not in MESSAGE_TYPE:
            return {'Error': 'Method Not Allowed'}, 405

        if method == 'createAndConfigureChatRoom':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True, help='Chat room jid cannot be blank')
            parser.add_argument('room_name', type=str, location='json', required=True, help='Room Name cannot be blank')
            parser.add_argument('room_desc', type=str, location='json', required=True,  help='Room Description cannot be blank')
            parser.add_argument('logging', type=str, location='json', required=True, help='Logging cannot be blank')
            parser.add_argument('invite', type=str, location='json', required=True, help='Invite cannot be blank')
            parser.add_argument('allow_pm', type=str, location='json', required=True, help='Allow pm cannot be blank')
            parser.add_argument('max_users', type=str, location='json', required=True, help='Max users cannot be blank')
            parser.add_argument('public_room', type=str, location='json', required=True,help='Public room cannot be blank')
            parser.add_argument('persistent_room', type=str, location='json', required=True,help='Persistent Room cannot be blank')
            parser.add_argument('moderated_room', type=str, location='json', required=True,help='Moderated Room cannot be blank')
            parser.add_argument('members_only', type=str, location='json', required=True,help='Memebers cannot be blank')
            parser.add_argument('disc_JID', type=str, location='json', required=True,help='Discover real JID cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;', (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)

                return
            cursor.close()

            if room is None:
                parser = reqparse.RequestParser()
                parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                    help='Chat room jid cannot be blank')

                xmpp.plugin['xep_0045'].joinMUC(args['chat_room_jid'], MANAGER['NICK'], wait=False)
                try:
                    xmpp.plugin['xep_0045'].setAffiliation(args['chat_room_jid'], MANAGER['JID'],
                                                           affiliation='owner')
                except (ValueError, TypeError) as error:
                    logger.exception(error)
                    logger.error('createAndConfigureChatRoom - Unsuccessfully processed - Set Affiliation')
                    return {'ack': 'true'}, 417

                xml = SERVICES['CHAT_MANAGER']['CHAT'].format(escape(str(args['room_name'])),
                                                              escape(str(args['room_desc'])),
                                                              escape(str(args['logging'])),
                                                              escape(str(args['invite'])),
                                                              escape(str(args['allow_pm'])),
                                                              escape(str(args['max_users'])),
                                                              escape(str(args['public_room'])),
                                                              escape(str(args['persistent_room'])),
                                                              escape(str(args['moderated_room'])),
                                                              escape(str(args['members_only'])),
                                                              escape(str(args['disc_JID'])))
                xml = ElementTree.Element(xml)
                conf = xmpp.plugin['xep_0004'].buildForm(xml)
                response = xmpp.plugin['xep_0045'].configureRoom(args['chat_room_jid'], conf)
                if response:
                    cursor = conn.cursor()
                    try:
                        cursor.execute("INSERT INTO CHAT_ROOM(CHAT_ROOM_JID, APP) VALUES (%s, %s);",
                                       (args['chat_room_jid'], app_name))
                        conn.commit()
                    except (pymysql.Error, Exception) as error:
                        conn.rollback()
                        cursor.close()
                        logger.exception(error)
                        return error_message('createAndConfigureChatRoom', 'Internal error', 500), 500
                    cursor.close()
                    logger.info('CREATE AND CONFIGURE ROOM - Successfully processed')
                    return {'ack': 'true'}, 200
                else:
                    xmpp.plugin['xep_0045'].leaveMUC(args['chat_room_jid'], MANAGER['NICK'])
                    logger.error('CREATE AND CONFIGURE ROOM - Unsuccessfully processed')

                    return {'ack': 'true'}, 417
            else:
                logger.error('CREATE AND CONFIGURE ROOM - Unsuccessfully processed - Room already exist')
                return {'ack': 'true'}, 417

        if method == 'leaveChatRoom':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                help='Chat room jid cannot be blank')
            parser.add_argument('user_nick', type=str, location='json', required=True,
                                help='Nick cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)
            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s', (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('chatRoom', 'Internal error', 500), 500

            cursor.close()

            if room is None:
                logger.error('LEAVE ROOM -  Unsuccessfully processed - Room does not exist')
                return {'ack': 'true'}, 417

            else:
                try:
                    response = xmpp.setRole(args['chat_room_jid'], args['user_nick'], 'none')
                except TypeError as error:
                    logger.exception(error)
                    return {'ack': 'true'}, 417
                if response:
                    logger.info('LEAVE ROOM - Successfully processed')
                    return {'ack': 'true'}, 200
                else:
                    logger.error('LEAVE ROOM -  Unsuccessfully processed')
                    return {'ack': 'true'}, 417

        if method == 'setRole':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                help='Chat room jid cannot be blank')
            parser.add_argument('nick', type=str, location='json', required=True,
                                help='Nick cannot be blank')
            parser.add_argument('role', type=str, location='json', required=True,
                                help='Role cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;', (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('chatRoom', 'Internal error', 500), 500

            cursor.close()

            if room is None:
                logger.error('SET ROLE -  Unsuccessfully processed - Room does not exist')
                return {'ack': 'true'}, 417
            else:
                try:
                    response = xmpp.setRole(args['chat_room_jid'], args['nick'], args['role'])
                except TypeError as error:
                    logger.exception(error)
                    return {'ack': 'true'}, 417
                if response:
                    logger.info('SET ROLE - Successfully processed')
                    return {'ack': 'true'}, 200
                else:
                    logger.error('SET ROLE -  Unsuccessfully processed')
                    return {'ack': 'true'}, 417

        if method == 'setAffiliation':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                help='Chat room jid cannot be blank')
            parser.add_argument('user_jid', type=str, location='json', required=True,
                                help='User jid cannot be blank')
            parser.add_argument('affiliation', type=str, location='json', required=True,
                                help='Affiliation cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;', (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('chatRoom', 'Internal error', 500), 500

            cursor.close()

            if room is None:
                logger.error('SET AFFILIATION -  Unsuccessfully processed - Room does not exist')
                return {'ack': 'true'}, 417

            else:
                try:
                    xmpp.plugin['xep_0045'].setAffiliation(str(args['chat_room_jid']), str(args['user_jid']),
                                                                      affiliation=str(args['affiliation']))
                except (ValueError, TypeError) as error:
                    logger.exception(error)
                    logger.error('SET AFFILIATION - Unsuccessfully processed')
                    return {'ack': 'true'}, 417
                else:
                    logger.info('SET AFFILIATION - Successfully processed')
                    return {'ack': 'true'}, 200

        if method == 'sendMessage':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                help='Chat room jid cannot be blank')
            parser.add_argument('message', type=str, location='json', required=True,
                                help='Message cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)

            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;', (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('chatRoom', 'Internal error', 500), 500

            cursor.close()
            if room is not None:
                xmpp.plugin['xep_0045'].joinMUC(args['chat_room_jid'], MANAGER['NICK'], wait=False)
                try:
                    xmpp.send_message(mto=args['chat_room_jid'],
                                      mbody=args['message'],
                                      mtype='groupchat')
                except Exception as error:
                    logger.exception(error)
                    logger.error('SEND MESSAGE - Unsuccessfully processed')
                    return {'ack': 'true'}, 417
                else:
                    logger.info('SEND MESSAGE - Successfully processed')
                    return {'ack': 'true'}, 200
            else:
                logger.error('SEND MESSAGE - Room does not exist!')
                return {'ack': 'true'}, 417

        if method == 'sendInvite':
            parser = reqparse.RequestParser()
            parser.add_argument('chat_room_jid', type=str, location='json', required=True,
                                help='Chat room jid cannot be blank')
            parser.add_argument('user_jid', type=str, location='json', required=True,
                                help='User jid cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)



            cursor = conn.cursor()
            try:
                cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s',
                               (args['chat_room_jid'], app_name))
                room = cursor.fetchone()
            except (pymysql.Error, Exception) as error:
                cursor.close()
                logger.exception(error)
                return error_message('chatRoom', 'Internal error', 500), 500


            if room is None:
                logger.info('SEND INVITE - Room does not exist!')
                return {'ack': 'true'}, 417

            else:
                xmpp.plugin['xep_0249'].send_invitation(args['user_jid'], args['chat_room_jid'])
                logger.info('SEND INVITE - Successfully processed')
                return {'ack': 'true'}, 200

        if method == 'createUser':
            parser = reqparse.RequestParser()
            parser.add_argument('username', type=str, location='json', required=True,
                                help='Username cannot be blank')
            parser.add_argument('password', type=str, location='json', required=True,
                                help='Password cannot be blank')
            parser.add_argument('access_token', type=str, location='json', required=True)
            args = parser.parse_args(strict=True)

            response = xmpp.register(args['username'], args['password'])

            return response

    @staticmethod
    @require_oauth('basic')
    def delete(app_name):
        parser = reqparse.RequestParser()
        parser.add_argument('chat_room_jid', type=str, location='args', required=True,
                            help='Chat room jid cannot be blank')
        parser.add_argument('access_token', type=str, location='args', required=True)
        args = parser.parse_args(strict=True)

        cursor = conn.cursor()
        try:
            cursor.execute('SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;', (args['chat_room_jid'], app_name))
            room = cursor.fetchone()
        except (pymysql.Error, Exception) as error:
            cursor.close()
            logger.exception(error)
            return error_message('chatRoom', 'Internal error', 500), 500

        if room is not None:
            xmpp.plugin['xep_0045'].joinMUC(args['chat_room_jid'], MANAGER['NICK'], wait=False)
            response = xmpp.plugin['xep_0045'].destroy(args['chat_room_jid'])

            if response:
                logger.info('Responde : {}'.format(response))
                try:
                    cursor.execute('DELETE FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s AND APP=%s;',
                                   (room[0], app_name))
                    conn.commit()
                except (pymysql.Error, Exception) as error:
                    cursor.close()
                    logger.exception(error)
                    return error_message('removeChatRoom', 'Internal error', 500), 500
                cursor.close()
                logger.info('REMOVE ROOM -  Successfully processed')
                return {'ack': 'true'}, 200
            else:
                logger.error('REMOVE ROOM -  Unsuccessfully processed')
                return {'ack': 'true'}, 417
        else:
            logger.error('REMOVE ROOM -  Unsuccessfully processed - Room does not exist')
            return {'ack': 'true'}, 417

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


api.add_resource(ChatManager, '/chatManager/v1.0/<method>', '/chatManager/v1.0/')
api.add_resource(Internal, '/chatManager/v1.0/internal/')
api.add_resource(Authorization, '/chatManager/v1.0/authorization/')
api.add_resource(AuthorizationManagment, '/chatManager/v1.0/authorization_managment/')

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    db.create_all()
    config = Configuration(filename='conf.ini')
    SERVICES = config.service_config
    user = User.query.filter_by(service_name='ChatManager').first()
    if not user:
        user = User(id=1, service_name='ChatManager')
        db.session.add(user)
        db.session.commit()

    MANAGER= SERVICES['CHAT_MANAGER']
    xmpp = Manager(MANAGER['JID'], MANAGER['PASSWORD'], MANAGER['NICK'])
    xmpp.register_plugin('xep_0030')  # Service Discovery
    xmpp.register_plugin('xep_0004')  # Data Forms
    xmpp.register_plugin('xep_0060')  # PubSub
    xmpp.register_plugin('xep_0199')  # XMPP Ping
    xmpp.register_plugin('xep_0045')
    xmpp.register_plugin('xep_0050')
    xmpp.register_plugin('xep_0249')
    xmpp.register_plugin('xep_0077')  # In-band Registration
    xmpp.register_plugin('xep_0080')
    xmpp.register_plugin('xep_0004')
    xmpp['xep_0030'].add_feature("jabber:iq:register")
    xmpp['xep_0077'].force_registration = True

    if xmpp.connect((MANAGER['SERVER'], 5222)):
        xmpp.process(block=False)
        xmpp.get_roster()
        xmpp.send_presence()
        xmpp.plugin['xep_0249'].plugin_init()
        enterAllMUC()
        logger.info("Done")
    else:
        logger.info("Unable to connect.")

    app.run(debug=False, host='0.0.0.0', port=5014, threaded=True)


