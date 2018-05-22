from xml.etree import ElementTree
import pymysql
import json
from configurationParser import Configuration
import logging
import coloredlogs
import sleekxmpp
from xml.sax.saxutils import escape
import sleekxmpp.componentxmpp
from sleekxmpp.exceptions import IqError, IqTimeout
import paho.mqtt.client as mqtt
import sys

logger = logging.getLogger('PresenceManagerLogger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('PresenceManagerLogger'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

conn = pymysql.connect(host='172.18.0.36', port=3306, user='presenceManager', passwd='presence', db='presence_db')

MESSAGE_TYPE = ['leaveChatRoom', 'status', 'getPresence', 'enterChatRoom']


CLIENT_ID = None
ACTIVE = False


class Manager(sleekxmpp.ClientXMPP):
    def __init__(self, jid, password, nick):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)
        self.jid = jid
        self.nick = nick
        self.add_event_handler("session_start", self.start)

    def muc_online(self, presence):
        if presence['muc']['nick'] != self.nick:
            logger.info('MUC - Online')
            chat_room_jid = presence['muc']['room']
            user_jid = presence['muc']['jid']
            dbManager(str(chat_room_jid), str(user_jid), 'online')

    def muc_offline(self, presence):
        if presence['muc']['nick'] != self.jid:
            logger.info('MUC - Offline')
            chat_room_jid = presence['muc']['room']
            user_jid = presence['muc']['jid']
            dbManager(str(chat_room_jid), str(user_jid), 'offline')


    def start(self, event):
        self.get_roster()
        self.send_presence()
        self.plugin['xep_0249'].plugin_init()


def dbManager(chat_room_jid, user_jid, state):
    logger.info('Chat Room JID - {}'.format(chat_room_jid))
    logger.info('User JID - {}'.format(user_jid))
    logger.info('State - {}'.format(state))
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM CHAT_PRESENCE WHERE CHAT_ROOM_JID = %s AND USER_JID = %s;", (chat_room_jid, user_jid))
    except (pymysql.Error, Exception) as error:
        cursor.close()
        logger.exception(error)
        return
    chat = cursor.fetchone()
    cursor.close()

    if chat is None:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO CHAT_PRESENCE(CHAT_ROOM_JID, USER_JID, STATE) VALUES (%s, %s, %s);", (chat_room_jid, user_jid, state))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return
        cursor.close()
    else:
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE CHAT_PRESENCE SET STATE = %s WHERE CHAT_ROOM_JID = %s AND USER_JID = %s;", (state, chat_room_jid, user_jid))
            conn.commit()
        except (pymysql.Error, Exception) as error:
            conn.rollback()
            cursor.close()
            logger.exception(error)
            return
        cursor.close()
    logger.info('Presence - Successfully processed')


def getPresence(chat_room_jid):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM CHAT_PRESENCE WHERE CHAT_ROOM_JID = %s;", str(chat_room_jid))
    except (pymysql.Error, Exception) as error:
        cursor.close()
        logger.exception(error)
        return {'type': 'getPresence', 'message': 'error', 'error_type': 'chatPresence'}
    room = cursor.fetchall()
    cursor.close()

    if room is None:
        logger.warning('GET PRESENCE - Unsuccessfully processed - Room does not exist')
        return {'type': 'getPresence', 'message': 'error', 'error_type': 'chatroomNotExist'}
    else:
        presence_values = []
        for x in room:
            logger.info(x)
            presence_values.append({"chat_room_jid": x[1], 'user_jid': x[2], 'presence': x[3]})
        logger.info('GET PRESENCE - Successfully processed')
        return {'type': 'getPresence', 'message': presence_values}


def enterAllMUC():
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT * FROM CHAT_ROOM;')
    except (pymysql.Error, Exception) as error:
        cursor.close()
        logger.exception(error)
        return
    rooms = cursor.fetchall()
    cursor.close()
    if rooms is not None:
        for room in rooms:
            logger.info('Presence Bot in room {}'.format(str(room[0])))
            xmpp.plugin['xep_0045'].joinMUC(str(room[0]), MANAGER['NICK'], wait=False)
            xmpp.add_event_handler("muc::%s::got_online" % str(room[0]), xmpp.muc_online,
                                   threaded=False)
            xmpp.add_event_handler("muc::%s::got_offline" % str(room[0]), xmpp.muc_offline,
                                   threaded=False)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        logger.info("connected OK Returned code=".format(rc))
        client.subscribe("chatManager/requests")
        client.subscribe("chatManager/status")

    else:
        logger.info("Bad connection Returned code=", rc)


def on_message(client, userdata, msg):
    global ACTIVE
    rcv_message = json.loads(msg.payload)
    if 'type' in rcv_message.keys():
        if rcv_message['type'] not in MESSAGE_TYPE:
            logger.info('Error Method Not Allowed')
            message = json.dumps({'type': 'params', 'message': 'error', 'error_type': 'methodNotAllowed'})
            client.publish('chatManager/response', message)
            return

        if rcv_message['type'] == 'status' and rcv_message['m_id'] != CLIENT_ID:
            if rcv_message['status'] == 'online':
                ACTIVE = False
            if rcv_message['status'] == 'offline':
                ACTIVE = True
                enterAllMUC()
                message = json.dumps({'type': 'status', 'm_id': CLIENT_ID, 'status': 'online'})
                client.publish('chatManager/status', message, retain=1)

        if ACTIVE:
            if rcv_message['type'] == 'enterChatRoom':
                if all(k in list(rcv_message.keys()) for k in ('chat_room_jid',)):
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s", (str(rcv_message['chat_room_jid']), ))
                    except (pymysql.Error, Exception) as error:
                        cursor.close()
                        logger.exception(error)
                        message = json.dumps({'type': 'enterChatRoom', 'message': 'error', 'error_type':'chatRoom'})
                        client.publish('chatManager/response', message)
                        return
                    room = cursor.fetchone()
                    cursor.close()

                    if room is None:
                        cursor = conn.cursor()
                        try:
                            cursor.execute("INSERT INTO CHAT_ROOM(CHAT_ROOM_JID) VALUES (%s);",
                                           (str(rcv_message['chat_room_jid']),))
                            conn.commit()
                        except (pymysql.Error, Exception) as error:
                            conn.rollback()
                            cursor.close()
                            logger.exception(error)
                            return {'type': 'enterChatRoom', 'message': 'error', 'error_type':'createChatroom'}
                        cursor.close()

                        xmpp.plugin['xep_0045'].joinMUC(str(rcv_message['chat_room_jid']), MANAGER['NICK'], wait=False)
                        xmpp.add_event_handler("muc::%s::got_online" % rcv_message['chat_room_jid'],
                                               xmpp.muc_online,
                                               threaded=False)
                        xmpp.add_event_handler("muc::%s::got_offline" % rcv_message['chat_room_jid'],
                                               xmpp.muc_offline,
                                               threaded=False)
                        
                        logger.info('Presence Bot in room {}'.format(str(rcv_message['chat_room_jid'])))
                        message = json.dumps({'type': 'enterChatRoom', 'message': 'successfully'})
                        client.publish('chatManager/response', message)
                    else:
                        logger.warning('Room already exist')
                        message = json.dumps({'type': 'enterChatRoom', 'message': 'unsuccessfully'})
                        client.publish('chatManager/response', message)
                else:
                    logger.error('Parameters do not fit to the specified for the operation: enterChatRoom')
                    message = json.dumps({'type': 'enterChatRoom', 'message': 'error', 'error_type':'parametersError'})
                    client.publish('chatManager/response', message)

            if rcv_message['type'] == 'leaveChatRoom':
                if all(k in list(rcv_message.keys()) for k in ('chat_room_jid',)):
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SELECT * FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s",
                                       (str(rcv_message['chat_room_jid']),))
                    except (pymysql.Error, Exception) as error:
                        cursor.close()
                        logger.exception(error)
                        message = json.dumps({'type': 'leaveChatRoom', 'message': 'error', 'error_type':'chatRoom'})
                        client.publish('chatManager/response', message)
                        return
                    room = cursor.fetchone()
                    cursor.close()

                    if room is None:
                        cursor = conn.cursor()
                        try:
                            cursor.execute("DELETE FROM CHAT_ROOM WHERE CHAT_ROOM_JID = %s;", (room[0],))
                            conn.commit()
                        except (pymysql.Error, Exception) as error:
                            cursor.close()
                            logger.exception(error)
                            message = json.dumps({'type': 'leaveChatRoom', 'message': 'error', 'error_type':'deleteChatroom'})
                            client.publish('chatManager/response', message)
                        cursor.close()

                        logger.error('LEAVE ROOM -  Unsuccessfully processed - Room does not exist')
                        message = json.dumps({'type': 'leaveChatRoom', 'message': 'error', 'error_type': 'chatroomNotExist'})
                        client.publish('chatManager/response', message)
                    else:
                        xmpp.plugin['xep_0045'].leaveMUC(str(rcv_message['chat_room_jid']), MANAGER['NICK'])
                        logger.info('LEAVE ROOM - Successfully processed')
                        message = json.dumps({'type': 'leaveChatRoom', 'message': 'successfully'})
                        client.publish('chatManager/response', message)

                else:
                    logger.error('Parameters do not fit to the specified for the operation: leaveChatRoom')
                    message = json.dumps({'type': 'leaveChatRoom', 'message': 'error', 'error_type':'parametersError'})
                    client.publish('chatManager/response', message)

            if rcv_message['type'] == 'getPresence':
                if all(k in list(rcv_message.keys()) for k in ('chat_room_jid',)):
                    presence_values = getPresence(rcv_message['chat_room_jid'])
                    logger.info(presence_values)
                    message = json.dumps(presence_values)
                    client.publish('chatManager/response', message)
                else:
                    logger.error('Parameters do not fit to the specified for the operation: getPresence')
                    message = json.dumps({'type': 'getPresence', 'message': 'error', 'error_type':'parametersError'})
                    client.publish('chatManager/response', message)
    else:
        logger.error('Parameters do not fit to the specified for the operation')

if __name__ == '__main__':
    logger.info(sys.argv)
    if sys.argv[1] == "id":
        CLIENT_ID = sys.argv[2]
    else:
        logger.warning('id is mandatory')
        exit()
    if len(sys.argv) > 3:
        if sys.argv[3] == "type":
            type_ = sys.argv[4]

    config = Configuration(filename='configuration.ini')
    SERVICES = config.service_config
    MANAGER = SERVICES['CHAT_MANAGER']
    MQTT = SERVICES['MQTT']

    client = mqtt.Client()
    message = json.dumps({'type': 'status', "m_id": CLIENT_ID, "status": "offline"})
    client.will_set("chatManager/status", message)
    try:
        client.connect(MQTT['URL'], int(MQTT['PORT']), keepalive=60)
        client.on_connect = on_connect
        client.on_message = on_message
    except Exception as e:
        if client is not None:
            client.reconnect()

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

    if xmpp.connect((MANAGER['SERVER'], 5222)):
        xmpp.process(block=False)
        logger.info('Connected to XMPP server')
    else:
        logger.error("Unable to connect.")


    if type_ == 'master':
        message = json.dumps({'type': 'status', 'm_id': CLIENT_ID, 'status': 'online'})
        client.publish('chatManager/status', message, retain=1)
        enterAllMUC()
        ACTIVE = True
    client.loop_forever()


