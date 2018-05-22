from flask import Flask, request
from configurationParser import Configuration
from datetime import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from xml.sax.saxutils import escape
from flask_oauthlib.client import OAuth
from math import sin, cos, sqrt, atan2, radians
from functools import wraps
from gevent import monkey, sleep
from threading import Thread
import paho.mqtt.client as paho
import requests
import grequests
import logging
import os
import time
import json
import coloredlogs

monkey.patch_all()

logger = logging.getLogger('AppServer Logger')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s', datefmt="%H:%M:%S")
ch.setFormatter(formatter)
logger.addHandler(ch)
coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - '
                                                      '%(message)s', datefmt="%H:%M:%S")

fileHandler = logging.FileHandler("{}.log".format('AppServer'))
fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

app = Flask('AppServer')
app.secret_key = 'development'
app.logger.addHandler(ch)
app.debug = False
bc_thread = None
# as client
oauth_client = OAuth(app)
context = {}
paho_request = 'chatManager/requests'
# km
DEFAULT_DISTANCE = 5
JWT = None
CREDENTIALS= {}

#TODO COPY LEAVE METHOD

class Background_Thread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.stop = False

    def run(self):
        while not self.stop and paho_client.loop() == 0:
            pass

def proceed_notifications(msg):
    global context
    logger.info('Context: {}'.format(context.__str__()))
    if 'message' in list(msg.keys()):
        logger.info('Message key exists')
        if msg['message']:
            event_id = int(msg['message'][0]['chat_room_jid'].split('@')[0])
            logger.info(event_id)
            if event_id in list(context.keys()):
                logger.info('Handle Single request {}'.format(context[event_id][0]['type']))
                logger.info('Message - {}'.format(msg['message'].__str__()))

                online = [x['user_jid'] for x in msg['message'] if x['presence'] == 'online']
                offline = [x['user_jid'].split('@')[0] for x in msg['message'] if x['presence'] == 'offline']
                logger.info('Online Users - {}'.format(len(online)))
                logger.info('Offline Users - {}'.format(len(offline)))
                logger.info(offline)
                logger.info(online)
                message = context[event_id][0]['message']

                if SERVICES['ChatManager']['BOT_JID'] in online:
                    online = [x for x in online if x != SERVICES['ChatManager']['BOT_JID']]
                    logger.info('Bot is here, but won\'t be considered')

                
                # TODO verify when phone is null
                user_profiling = requests.get(SERVICES['UserProfilingService']['GET_PHONE'], params={'access_token': STATE['UserProfilingService'][1]})
                if user_profiling.status_code == 200:
                    phone_numbers = user_profiling.json()['mobile_numbers']
                    logger.info('Phone numbers {}'.format(phone_numbers.__str__()))
                    intersect = [x['phone'] for x in phone_numbers if x['user_id'] in offline]
                    logger.info(intersect)
                    if intersect != []:
                        sms = requests.post(SERVICES['SmsManagerService']['POST'], json={'mobile_nr_list': intersect,
                                                                                   'message': message, 
                                                                                   'access_token': STATE['SmsManagerService'][1]})
                        if sms.status_code == 200:
                            logger.info('Sent sms notification successfully')
                        else:
                            logger.warning('Not send sms notification')
                    else:
                        logger.warning('Empty list, check it pls.')
                else:
                    logging.warning('Could not get users phone numbers, aborting notification send')
                
                chat_room_jid = str(event_id) + '@conference.test'
                logger.info('Chat room jid: {}'.format(chat_room_jid))

                # Send message
                chat_manager = requests.post(SERVICES['ChatManager']['SEND_MESSAGE'], json={'chat_room_jid': chat_room_jid,
                                                                                            'message': message,
                                                                                            'access_token': STATE['ChatManager'][1]})
                if chat_manager.status_code == 200:
                    logger.info('Message Sent to {}'.format(chat_room_jid))
                else:
                    logger.warning('Message not sent')
                del context[event_id]
                logger.info('Deleted reminder for event {}'.format(event_id))
                return
            logger.info('Event id {} does not exist'.format(event_id))
            return
        else:
            logger.info('List in message key is empty')
    logger.info('Invalid message, message key does not exist')


def generic_function(msg):
    logger.info("type:{} - message: {}".format(msg['type'], msg['message']))
    

def on_message(client, user_data, msg):
    redirect = {'getPresence': proceed_notifications, 'generic_function': generic_function}
    message = json.loads(msg.payload)
    logger.info('Message: {}'.format(message.__str__()))
    if 'type' in list(message.keys()):
        msg_type = message['type']
        if msg_type == 'getPresence':
            logger.info('Redirecting  - Handle Notification')
            return redirect[msg_type](message)
        else:
            logger.info('Redirecting - Info handler - Generic Function')
            return redirect['generic_function'](message)
    logger.info('Invalid message, type key does not exist')


def build_remote_app(consumer_key, consumer_secret, request_token_params, service):
    remote = oauth_client.remote_app(
        service,
        consumer_key=consumer_key,
        consumer_secret=consumer_secret,
        request_token_params=request_token_params,
        base_url=SERVICES['APPSERVER']['HOST'],
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


def login(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'fb_access_token', 'expires_in')):
        user_id = body_payload['user_id']
        access_token = body_payload['fb_access_token']
        expires_in = body_payload['expires_in']
        logger.info('Starting login for user {}'.format(user_id))
        validate = requests.post(SERVICES['FacebookService']['ALL'], json={'access_token': access_token,
                                                                    'id': user_id,
                                                                    'expires_in': expires_in,
                                                                    'access_token_': STATE['FacebookService'][1]})
        if validate.status_code == 200:
            response = validate.json()
            logger.info('Login successfully done.')
            
            chat_manager = requests.post(SERVICES['ChatManager']['CREATE_USER'], json={'username': user_id,
                                                                                        'password': user_id,
                                                                                        'access_token': STATE['ChatManager'][1]})
            if chat_manager.status_code == 200:
                logger.info('User {} created - XMPP'.format(user_id))
            else:
                logger.warning('User {} NOT created - XMPP'.format(user_id))
            

            logger.info('Adding user to user profiling..')
            user_profiling = requests.post(SERVICES['UserProfilingService']['CREATE_USER'],
                                           json={'user_id': user_id,
                                                 'mail': response['email'],
                                                 'access_token': STATE['UserProfilingService'][1]})
            if user_profiling.status_code == 200:
                logger.info('User - UserProfiling successfully')
                return {'ack': 'true'}
            else:
                logger.info('User - UserProfiling erro')
                return {'ack': 'false'}
                
        else:
            logger.warning('Login unsuccessfully for user {}'.format(user_id))
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Login(user_id, access_token, '
                       'expires_in)')


def create_event(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('name', 'type', 'activity', 'maxppl', 'minppl', 'owner',
                                                    'description', 'locations', 'locations_priority', 'schedules',
                                                    'schedules_priority', 'decision')):
        name = body_payload['name']
        type_ = body_payload['type']
        activity = body_payload['activity']
        maxppl = body_payload['maxppl']
        minppl = body_payload['minppl']
        owner = body_payload['owner']
        description = body_payload['description']
        locations = body_payload['locations']
        locations_priority = body_payload['locations_priority']
        schedules = body_payload['schedules']
        schedules_priority = body_payload['schedules_priority']
        decision = body_payload['decision']
        logger.info('Creating event')
        events_manager = requests.post(SERVICES['EventsManagerService']['CREATE_EVENT'],
                                       json={'name': name,
                                             'type': type_,
                                             'activity': activity,
                                             'maxppl': maxppl,
                                             'minppl': minppl,
                                             'owner': owner,
                                             'description': description,
                                             'access_token': STATE['EventsManagerService'][1]})
        if events_manager.status_code == 200:
            event_id = events_manager.json()['events_id']
            logger.info('Event create successfully, got id: {}'.format(event_id))

            chat_room_jid = str(event_id) + '@conference.test'
            message_= {'chat_room_jid': chat_room_jid, 
                        'room_name': name, 
                        'room_desc': description, 
                        'logging':1, 
                        'invite':1, 
                        'allow_pm':'anyone', 
                        'max_users': 50, 
                        'public_room': 1, 
                        'persistent_room': 1,
                        'moderated_room': 0, 
                        'members_only': 0, 
                        'disc_JID':'anyone',
                        'access_token': STATE['ChatManager'][1] }

            chat_room_jid = str(event_id) + '@conference.test'
            
            chat_manager = requests.post(SERVICES['ChatManager']['CREATE_GROUP'], json=message_)
            if chat_manager.status_code == 200:
                logger.info('Group {} created - XMPP'.format(chat_room_jid))
        
               
                user_jid = str(owner)+'@test'
                chat_manager = requests.post(SERVICES['ChatManager']['SEND_INVITE'], json={'chat_room_jid': chat_room_jid,
                                                                                                'user_jid': user_jid,
                                                                                                'access_token': STATE['ChatManager'][1]})

                if chat_manager.status_code == 200:
                    logger.info('Invite sent to User {} - XMPP'.format(user_jid))
                    paho_client.publish(paho_request, json.dumps({'type': 'enterChatRoom', 'chat_room_jid': chat_room_jid}))
                else:
                    logger.warning('Invite NOT sent to User {} - XMPP'.format(user_jid))

            else:
                logger.warning('Group {} NOT created - XMPP'.format(chat_room_jid))
                logger.info('{}'.format(chat_room_jid))

            # weather
            # 18:30 23/01/2017
            decision_timestamp = datetime.strptime(decision, '%H:%M %d/%m/%Y')
            set_locations = []
            logger.info('Looking up locations')
            for location in locations:
                geocode = requests.get(SERVICES['GeolocationService']['LOOKUP'],
                                        params={'access_token': STATE['GeolocationService'][1], 'lat': location[0], 'lng': location[1]})
                if geocode.status_code == 200:
                    set_locations.append([location[0], location[1], geocode.json()['msg']['local_name'],
                                          geocode.json()['msg']['city']])
                else:
                    logger.info('Failed look up for location - lat:{}, long:{}'.format(location[0], location[1]))
                    logger.info('Rolling back all transactions')
                    events_manager = requests.delete(SERVICES['EventsManagerService']['DELETE_EVENT'],
                                                    params={'access_token': STATE['EventsManagerService'][1], 'event_id': event_id,
                                                         'user_id': owner})
                    if events_manager.status_code == 200:
                        logger.info('Event deleted successfully')
                        return {'ack': 'false'}
                    else:
                        logger.info('Could not delete event')
                        return {'ack': 'false'}
            logger.info('Process schedule event creation')
            schedule_manager = grequests.post(SERVICES['ScheduleManager']['START_SCHEDULE'],
                                              json={'request_id': event_id,
                                                    'timestamp': decision_timestamp.strftime('%s'),
                                                    'access_token': STATE['ScheduleManager'][1]})
            logger.info('Process location event creation')
            event_location = grequests.post(SERVICES['LocationsService']['ADD_EVENT'],
                                            json={'event_id': event_id,
                                                  'timestamp': decision_timestamp.strftime('%s'),
                                                  'access_token': STATE['LocationsService'][1]})
            alarm_manager = grequests.post(SERVICES['AlarmManager']['CREATE_ALARM'], json={'datetime': decision,
                                                                                    'id': event_id,
                                                                                    'access_token': STATE['AlarmManager'][1]})
            reqs = [schedule_manager, event_location, alarm_manager]
            response = grequests.map(reqs)
            flag = all([True for x in response if x.status_code == 200])
            if flag:
                logger.info('All processes concluded with success')
                logger.info('Process places')
                for i in range(len(set_locations)):
                    location_manager = requests.post(SERVICES['LocationsService']['ADD_LOCATION'],
                                                     json={'event_id': event_id,
                                                           'lat': set_locations[i][0],
                                                           'long': set_locations[i][1],
                                                           'priority': locations_priority[i],
                                                           'city': set_locations[i][3],
                                                           'access_token': STATE['LocationsService'][1]})
                    if location_manager.status_code == 200:
                        logger.info('Location added successfully')
                    else:
                        logger.warning('Location lat:{}, long:{}, city:{} not added'.format(set_locations[i][0],
                                                                                            set_locations[i][1],
                                                                                            set_locations[i][3]))
                logger.info('Process schedules')
                for i in range(len(schedules)):
                    schedule_manager = requests.post(SERVICES['ScheduleManager']['ADD_SCHEDULE'],
                                                     json={'request_id': event_id, 'timestamp': schedules[i],
                                                           'priority': schedules_priority[i],
                                                           'access_token': STATE['ScheduleManager'][1]})
                    if schedule_manager.status_code == 200:
                        logger.info('Schedule added successfully')
                        logger.info(schedule_manager.json())
                    else:
                        logger.warning('Schedule {} not added'.format(schedules[i]))
                logger.info('Event id that will be returned: {}'.format(event_id))
                return {'ack': 'true',
                        'event_id': event_id}
            else:
                logger.warning('One of the processes failed. Rollback started')
                # TODO
        else:
            logger.warning('Event not created')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Create Event')


def update_event(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'event_id', 'name', 'type', 'activity', 'maxppl',
                                                    'minppl', 'atmppl', 'description')):
        user_id = body_payload['user_id']
        event_id = body_payload['event_id']
        name = body_payload['name']
        type_ = body_payload['type']
        activity = body_payload['activity']
        maxppl = body_payload['maxppl']
        minppl = body_payload['minppl']
        atmppl = body_payload['atmppl']
        description = body_payload['description']
        events_manager = requests.post(SERVICES['EventsManagerService']['UPDATE_EVENT'],
                                       json={'user_id': user_id,
                                             'event_id': event_id,
                                             'name': name,
                                             'type': type_,
                                             'activity': activity,
                                             'maxppl': maxppl,
                                             'minppl': minppl,
                                             'atmppl': atmppl,
                                             'description': description,
                                             'access_token': STATE['EventsManagerService'][1]})
        if events_manager.status_code == 200:
            logger.info('Event {} updated successfully.'.format(event_id))
            return {'ack': 'true'}
        else:
            logger.warning('Event {} not updated'.format(event_id))
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Update Event')


def get_distance(lat1, lon1, lat2, lon2, radius):
    r = 6373.0
    dlon = radians(float(lon2)) - radians(float(lon1))
    dlat = radians(float(lat2)) - radians(float(lat1))
    aux = (sin(dlat / 2)) ** 2 + cos(float(lat1)) * cos(float(lat2)) * (sin(dlon / 2)) ** 2
    c = 2 * atan2(sqrt(aux), sqrt(1 - aux))
    distance = r * c
    logger.info('Radius - {} Distance - {}'.format(radius, distance))
    return True if distance <= float(radius) else False


def search(body_payload):
    events = {}
    if all(k in list(body_payload.keys()) for k in ('user_id', 'lat', 'long')):
        user_id = body_payload['user_id']
        lat = body_payload['lat']
        lng = body_payload['long']
        geolocation_manager = requests.post(SERVICES['GeolocationService']['USER_LOCATION'], json={'user_id': user_id,
                                                                                            'lat': lat, 'lng': lng,
                                                                                            'access_token': STATE['GeolocationService'][1]})
        logger.warning(geolocation_manager.status_code)
        if geolocation_manager.status_code == 200:
            if all(k in list(body_payload.keys()) for k in ('zone', 'distance', 'activity')):
                zone = body_payload['zone']
                activity = body_payload['activity']
                if zone != "":
                    logger.warning("zoneee")
                    if activity != "":
                        logger.warning("activity")
                        events_manager = grequests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                                        params={'access_token': STATE['EventsManagerService'][1],
                                                        'op_type': 'publicByActivity',
                                                        'activity': activity})

                        location_manager = grequests.get(SERVICES['LocationsService']['GET_MOST_VOTED'],
                                                         params={'access_token': STATE['LocationsService'][1],
                                                         'zone': zone})
                        geolocation = grequests.get(SERVICES['GeolocationService']['GEOCODE'],
                                                    params={'access_token': STATE['GeolocationService'][1],
                                                    'address': zone})

                        reqs = [events_manager, location_manager, geolocation]
                        response = grequests.map(reqs)
                        flag = all([True for x in response if x.status_code == 200])
                        if flag:
                            if body_payload['distance'] != "":
                                distance = body_payload['distance']
                            else:
                                distance = DEFAULT_DISTANCE

                            events_id_list = list(response[0].json()['events'])
                            intersect = [x for x in events_id_list if str(x[0]) in list(response[1].json().keys())]

                            print(response[2].json()['msg'])

                            for k in intersect:
                                v = response[1].json()[str(k[0])]
                                print(type(k[1]), type(k[2]))
                                tmp = []
                                for x in v:
                                    if get_distance(response[2].json()['msg']['lat'], response[2].json()['msg']['long'],
                                                    x[0], x[1], distance):
                                        tmp.append([x[0], x[1]])
                                if tmp:
                                    tmp.append({'name': k[1]})
                                    tmp.append({'activity': k[2]})
                                    tmp.append({'zone': response[2].json()['msg']})
                                    events[str(k[0])] = tmp
                            logger.warning('Returned events {}'.format(events.__str__()))
                            return events
                        else:
                            logger.warning('Public Events - Location')
                            return

                    # no activity

                    events_manager = grequests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                                   params={'access_token': STATE['EventsManagerService'][1],
                                                   'op_type': 'publicEvents'})
                    location_manager = grequests.get(SERVICES['LocationsService']['GET_MOST_VOTED'],
                                                     params={'access_token': STATE['LocationsService'][1],
                                                     'zone': zone})
                    geolocation = grequests.get(SERVICES['GeolocationService']['GEOCODE'],
                                                params={'access_token': STATE['GeolocationService'][1],
                                                'address': zone})

                    reqs = [events_manager, location_manager, geolocation]
                    response = grequests.map(reqs)
                    flag = all([True for x in response if x.status_code == 200])
                    logger.warning(flag)
                    if flag:
                        if body_payload['distance'] != "":
                            distance = body_payload['distance']
                        else:
                            distance = DEFAULT_DISTANCE

                        logger.warning(response[0].json())
                        logger.warning(response[1].json())
                        logger.warning(response[2].json())
                        events_id_list = list(response[0].json()['events'])
                        logger.warning(events_id_list)
                        logger.warning(list(response[1].json().keys()))
                        intersect = [x for x in events_id_list if str(x[0]) in list(response[1].json().keys())]
                        logger.warning(intersect)
                        for k in intersect:
                            tmp = []
                            logger.warning(response[1].json())
                            v = response[1].json()[str(k[0])]
                            logger.warning(v)
                            for x in v:
                                if get_distance(response[2].json()['msg']['lat'], response[2].json()['msg']['long'],
                                                x[0], x[1], distance):
                                    tmp.append([x[0], x[1]])
                            if tmp:
                                tmp.append({'name': k[1]})
                                tmp.append({'activity': k[2]})
                                tmp.append({'zone': response[2].json()['msg']})
                                events[str(k[0])] = tmp
                        logger.warning('Returned events {}'.format(events.__str__()))
                        return events
                    else:
                        logger.warning('Public Events - Location')
                        return
                # no zone, activity
                if activity != "":
                    events_manager = grequests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                                    params={'access_token': STATE['EventsManagerService'][1],
                                                    'op_type': 'publicByActivity',
                                                    'activity': activity})
                    location_manager = grequests.get(SERVICES['LocationsService']['GET_MOST_VOTED'])

                    reqs = [events_manager, location_manager]
                    response = grequests.map(reqs)
                    flag = all([True for x in response if x.status_code == 200])
                    if flag:
                        if body_payload['distance'] != "":
                            distance = body_payload['distance']
                        else:
                            distance = DEFAULT_DISTANCE

                        events_id_list = list(response[0].json()['events'])
                        intersect = [x for x in events_id_list if str(x[0]) in list(response[1].json().keys())]

                        for k in intersect:
                            tmp = []
                            v = response[1].json()[str(k[0])]
                            for x in v:
                                if get_distance(lat, lng, x[0], x[1], distance):
                                    tmp.append([x[0], x[1]])
                            if tmp:
                                tmp.append({'name': k[1]})
                                tmp.append({'activity': k[2]})
                                events[str(k[0])] = tmp
                        logger.warning('Returned events {}'.format(events.__str__()))
                        return events
                    else:
                        logger.warning('Public Events - Location')
                        return
                # no zone, no activity
                events_manager = grequests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                               params={'access_token': STATE['EventsManagerService'][1],
                                               'op_type': 'publicEvents'})

                location_manager = grequests.get(SERVICES['LocationsService']['GET_MOST_VOTED'], 
                                            params={'access_token': STATE['LocationsService'][1]})

                reqs = [events_manager, location_manager]
                response = grequests.map(reqs)

                flag = all([True for x in response if x.status_code == 200])

                if flag:
                    if body_payload['distance'] != "":
                        distance = body_payload['distance']
                    else:
                        distance = DEFAULT_DISTANCE

                    events_id_list = list(response[0].json()['events'])
                    intersect = [x for x in events_id_list if str(x[0]) in list(response[1].json().keys())]
                    for k in intersect:
                        tmp = []
                        v = response[1].json()[str(k[0])]
                        for x in v:
                            if get_distance(lat, lng, x[0], x[1], distance):
                                tmp.append([x[0], x[1]])
                        if tmp:
                            tmp.append({'name': k[1]})
                            tmp.append({'activity': k[2]})
                            events[str(k[0])] = tmp
                    logger.warning('Returned events {}'.format(events.__str__()))
                    return events
                else:
                    logger.warning('Public Events - Location')
            else:
                logger.warning('zone, distance, activity missing')
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Search')


def update_user(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'username', 'tlm')):
        user_id = body_payload['user_id']
        username = body_payload['username']
        tlm = body_payload['tlm']
        logger.info('Updating user information')
        user_profiling = requests.post(SERVICES['UserProfilingService']['UPDATE_USER'],
                                       json={'user_id': user_id,
                                             'username': username,
                                             'tlm': tlm,
                                             'access_token': STATE['UserProfilingService'][1]})
        status_code = user_profiling.status_code
        if status_code == 200:
            logger.info('Update successfully done')
            return user_profiling.json()
        else:
            logger.info('Could not process the update')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Update User')


def add_user(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'event_id')):
        user_id = body_payload['user_id']
        event_id = body_payload['event_id']
        logger.info('Adding user {} to group {}'.format(user_id, event_id))
        events_manager = requests.post(SERVICES['EventsManagerService']['ADD_USER'], json={'user_id': user_id,
                                                                             'event_id': event_id,
                                                                             'access_token': STATE['EventsManagerService'][1]})
        status_code = events_manager.status_code
        if status_code == 200:
            chat_room_jid = str(event_id) + '@conference.test'
            user_jid = str(user_id)+'test'
            chat_manager = requests.post(SERVICES['ChatManager']['SEND_INVITE'], json={'chat_room_jid': chat_room_jid,
                                                                                            'user_jid': user_jid,
                                                                                            'access_token': STATE['ChatManager'][1]})
            if chat_manager.status_code == 200:
                logger.info('Invite sent to User {} - XMPP'.format(user_jid))
            else:
                logger.warning('Invite NOT sent to User {} - XMPP'.format(user_jid))

            return events_manager.json()
        else:
            logger.warning('User not added')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Add User')


def update_schedule(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('event_id', 'timestamp')):
        event_id = body_payload['event_id']
        timestamp = datetime.strptime(body_payload['timestamp'], '%H:%M %d/%m/%Y')

        logger.info('Updating schedule {} for event {}'.format(timestamp, event_id))
        schedule_manager = requests.post(SERVICES['ScheduleManager']['ADD_SCHEDULE'], json={'request_id': event_id,
                                                                                     'timestamp': timestamp.strftime(
                                                                                         '%s'),
                                                                                     'access_token': STATE['ScheduleManager'][1]})
        status_code = schedule_manager.status_code
        if status_code == 200:
            logger.info('Update successfully')
            return schedule_manager.json()
        else:
            logger.warning('Update unsuccessfully')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Update scheduler')


def vote_datetime(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('event_id', 'timestamp')):
        event_id = body_payload['event_id']
        #timestamp = datetime.strptime(body_payload['timestamp'], '%H:%M %d/%m/%Y')
        timestamp =  body_payload['timestamp']
        logger.info('Process schedule voting for event {}'.format(event_id))
        schedule_manager = requests.post(SERVICES['ScheduleManager']['VOTE_SCHEDULE'], json={'request_id': event_id,
                                                                                      'timestamp': timestamp,
                                                                                      'access_token': STATE['ScheduleManager'][1]})
        status_code = schedule_manager.status_code
        if status_code == 200:
            logger.info('Successfully vote for schedule {} related to event {}'.format(timestamp, event_id))
            return schedule_manager.json()
        else:
            logger.warning('Unsuccessfully vote for schedule {} related to event {}'.format(timestamp, event_id))
            return {'ack': 'true'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Vote Scheduler')


def get_groups(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id',)):
        user_id = body_payload['user_id']
        logger.info('Getting user events')
        events_manager = requests.get(SERVICES['EventsManagerService']['GET_EVENTS'], params={'access_token': STATE['EventsManagerService'][1],
                                                                                    'user_id': user_id})
        status_code = events_manager.status_code
        if status_code == 200:
            logger.info('Events successfully')
            return events_manager.json()
        else:
            logger.info('Events unsuccessfully')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Get User Groups')


def get_group(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('event_id',)):
        event_id = body_payload['event_id']
        logger.info('Getting event {} information(location, schedules, general)'.format(event_id))
        events_manager = grequests.get(SERVICES['EventsManagerService']['GET_USERS'], 
                                                                              params={'access_token': STATE['EventsManagerService'][1],
                                                                              'op_type': 'event_info',
                                                                              'event_id': event_id})
        location_manager = grequests.get(SERVICES['LocationsService']['GET_ALL'],
                                                                            params={'access_token': STATE['LocationsService'][1],
                                                                            'event_id': event_id})
        schedule_manager = grequests.get(SERVICES['ScheduleManager']['GET_SCHEDULE'],
                                                                            params={'access_token': STATE['ScheduleManager'][1],
                                                                            'request_id': event_id})
        logger.info(schedule_manager)
        reqs = [events_manager, location_manager, schedule_manager]
        response = grequests.map(reqs)
        flag = all([True for x in response if x.status_code == 200])
        if flag:
            logger.info('Got information successfully')
            response = [x.json() for x in response]
            location = response[1]['locations']
            schedule = response[2]
            weather_responses = []
            logger.info(len(response[1]['locations']))
            for i in range(len(response[1]['locations'])):
                lat_tmp = location[i][0]
                lng_tmp = location[i][1]
                day = str(datetime.fromtimestamp(schedule[i][0]).day)
                hour = str(datetime.fromtimestamp(schedule[i][0]).hour)
                r = requests.post(SERVICES['WeatherProxy']['GET_WEATHER'], json={'lat': lat_tmp,
                                                                    'long': lng_tmp,
                                                                    'day': day,
                                                                    'hour': hour,
                                                                    'access_token': STATE['WeatherProxy'][1]})
                weather_responses.append(r.json())
            return dict(name=response[0]['info'][0], description=response[0]['info'][1],
                        activity=response[0]['info'][2],
                        atm=response[0]['info'][3], locations=response[1]['locations'],
                        schedules=response[2], weather = weather_responses)
        else:
            logger.warning('Could not get the information')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Get Single Group')


def vote_local(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('event_id', 'lat', 'long')):
        lat = body_payload['lat']
        lng = body_payload['long']
        event_id = body_payload['event_id']
        logger.info('Process location voting for event {}'.format(event_id))
        location_manager = requests.post(SERVICES['LocationsService']['VOTE_LOCATION'], json={'event_id': event_id,
                                                                                      'lat': lat,
                                                                                      'long': lng,
                                                                                      'access_token': STATE['LocationsService'][1]})
        if location_manager.status_code == 200:
            logger.info('Successfully vote for location lat: {}, long: {} related to event: {}'.format(lat, lng,
                                                                                                       event_id))
            return location_manager.json()
        else:
            logger.info('Unsuccessfully vote for location lat: {}, long: {} related to event: {}'.format(lat, lng,
                                                                                                         event_id))
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Vote location')


def add_location(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('event_id', 'lat', 'long', 'priority', 'city')):
        event_id = body_payload['event_id']
        priority = body_payload['priority']
        lat = body_payload['lat']
        lng = body_payload['long']
        city = body_payload['city']
        logger.info('Adding location lat: {}, long: {} related to event {}'.format(lat, lng, event_id))
        location_manager = requests.post(SERVICES['LocationsService']['ADD_LOCATION'], json={'event_id': event_id,
                                                                                     'lat': lat,
                                                                                     'long': lng,
                                                                                     'priority': priority,
                                                                                     'city': city,
                                                                                     'access_token': STATE['LocationsService'][1]})
        if location_manager.status_code == 200:
            logger.info('Location successfully added')
            return location_manager.json()
        else:
            logger.warning('Location unsuccessfully added')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Add location')


def notifications_manager(body_payload):
    global context
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('type', 'event_id')):
        type_ = body_payload['type']
        event_id = body_payload['event_id']
        if type_ == 'decision':
            logger.info('Decision day for event {}'.format(event_id))
            req_schedule = grequests.get(SERVICES['ScheduleManager']['MOST_VOTED'], params={'access_token': STATE['ScheduleManager'][1], 'request_id': event_id})
            req_location = grequests.get(SERVICES['LocationsService']['MOST_VOTED'], params={'access_token': STATE['LocationsService'][1], 'event_id': event_id})
            reqs = [req_schedule, req_location]
            response = grequests.map(reqs)
            flag = all([True for x in response if x.status_code == 200])
            if flag:
                logger.info('Got schedule and location for event {}'.format(event_id))
                timestamp = response[0].json()['timestamp']
                lat = response[1].json()['most_voted'][0]
                lng = response[1].json()['most_voted'][1]
                local = requests.get(SERVICES['GeolocationService']['LOOKUP'], params={'access_token': STATE['GeolocationService'][1], 'lat': lat, 'lng': lng})
                if local.status_code == 200:
                    local = local.json()['msg']['local_name']
                    events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'], params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'eventName',
                                                                                         'event_id': event_id})
                    if events_manager.status_code == 200:
                        event_name = events_manager.json()['eventName']
                        events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                                    params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'participants',
                                                            'event_id': event_id})
                        if events_manager.status_code == 200:
                            users = events_manager.json()['users']
                            message = 'Event {} will take place in {} on {}.'.format(event_name, str(local),
                                                                                     datetime.fromtimestamp(timestamp))
                            logger.info(message)
                            push = requests.post(SERVICES['PushNotificationService']['POST'], json={'access_token': STATE['PushNotificationService'][1], 'topic': event_id, 'message': message})
                            if push.status_code == 200:
                                logger.info('Push notification sent.')
                                return {'ack': 'true'}
                            else:
                                logger.info('Push notification NOT sent.')
                                return {'ack': 'true'}
                        else:
                            logging.warning('Could not get event users, aborting notification send')
                            return {'ack': 'false'}
                    else:
                        logging.warning('Could not event name, aborting notification send')
                        return {'ack': 'false'}
                else:
                    logging.warning('Could not event lookup location, aborting notification send')
                    return {'ack': 'false'}
            else:
                logging.warning('Could not event decision information, aborting notification send')
                return {'ack': 'false'}
        if type_ == 'weather':
            message = body_payload['message']
            events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'], 
                                                                                 params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'eventName',
                                                                                 'event_id': event_id})
            if events_manager.status_code == 200:
                event_name = events_manager.json()['eventName']
                events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                              params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'participants', 'event_id': event_id})
                if events_manager.status_code == 200:
                    users = events_manager.json()['users']
                    message = event_name + ' ' + message
                    logger.info(message)
                    push = requests.post(SERVICES['PushNotificationService']['POST'], json={'access_token': STATE['PushNotificationService'][1], 'topic': event_id, 'message': message})
                    if push.status_code == 200:
                        logger.info('Push notification sent.')
                        return {'ack': 'true'}
                    else:
                        logger.info('Push notification NOT sent.')
                        return {'ack': 'true'}
                else:
                    logging.warning('Could not get event users, aborting notification send')
                    return {'ack': 'false'}
            else:
                logging.warning('Could not event name, aborting notification send')
                return {'ack': 'false'}

        if type_ == 'reminder':
            events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'],
                                                                                 params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'eventName',
                                                                                 'event_id': event_id})
            if events_manager.status_code == 200:
                event_name = events_manager.json()['eventName']
                message = '{} - 1 hour left.'.format(event_name)
                if event_id in list(context.keys()):
                    context[event_id].append({'type': 'reminder',
                                            'message': message})
                else:
                    context[event_id] = [{'type': 'reminder',
                                            'message': message}]

                chat_room_jid = str(event_id) + '@conference.test'
                logger.info('Send Presence Request - chat room {}'.format(chat_room_jid))
                paho_client.publish(paho_request, json.dumps({'type': 'getPresence', 'chat_room_jid': chat_room_jid}))
                return 
            else:
                logging.warning('Could not get event name, aborting notification send')
                return {'ack': 'false'}

        if type_ == 'closed_event':
            events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'], params={'access_token': STATE['EventsManagerService'][1], 'op_type': 'eventName',
                                                                                 'event_id': event_id})
            if events_manager.status_code == 200:
                event_name = events_manager.json()['eventName']
                message = '{} - has started.'.format(event_name)
                if event_id in list(context.keys()):
                    context[event_id].append({'type': 'closed_event',
                                            'message': message})
                else:
                    context[event_id] = [{'type': 'closed_event',
                                            'message': message}]

                chat_room_jid = str(event_id) + '@conference.test'
                logger.info('Send Presence Request - chat room {}'.format(chat_room_jid))
                paho_client.publish(paho_request, json.dumps({'type': 'getPresence', 'chat_room_jid': chat_room_jid}))
                return
            else:
                logging.warning('Could not get event name, aborting notification send')
                return {'ack': 'false'}
        else:
            logging.warning('Invalid notification method.')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation:  Notification Manager')

def invite_friends(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'event_id')):
        user_id = body_payload['user_id']
        event_id = body_payload['event_id']
        user_profiling = requests.get(SERVICES['UserProfilingService']['GET_ALL'],
                                           params={'user_id': user_id,
                                                 'access_token': STATE['UserProfilingService'][1]})
        if user_profiling.status_code == 200:
            logger.info('User info - successfully')
            user_profiling = user_profiling.json()
            logger.info('User - {}'.format(user_profiling.__str__()))

            events_manager = requests.get(SERVICES['EventsManagerService']['GET_USERS'], 
	                                                                              params={'access_token': STATE['EventsManagerService'][1],
	                                                                              'op_type': 'event_info',
	                                                                              'event_id': event_id})
            if events_manager.status_code == 200:
                logger.info('Event info - successfully')
                events_manager = events_manager.json()
                event_type = events_manager['info'][4]
                if event_type == 0:
                    message = '{} invited you to join the event. It is public and the activity will be {}.'.format(user_profiling['userProfile'][1], events_manager['info'][2])
                else:
                    message = '{} invited you to join the event. It is private and the activity will be {}.'.format(user_profiling['userProfile'][1], events_manager['info'][2])
		        
                logger.info('Getting all friends of {}'.format(user_id))
                fb = requests.get(SERVICES['FacebookService']['ALL'], params={'id': user_id, 'access_token': STATE['FacebookService'][1]})
                if fb.status_code == 200:
                    friends = fb.json()['msg']
                    for friend in friends:
                        push = requests.post(SERVICES['PushNotificationService']['POST'], json={'access_token': STATE['PushNotificationService'][1], 'topic': event_id, 'message': message})
                        if push.status_code == 200:
                            logger.info('Push notification sent.')
                            return {'ack': 'true'}
                        else:
                            logger.info('Push notification NOT sent.')
                            return {'ack': 'true'}
                else:
                    logger.info('Error Facebook')
                    return {'ack': 'false'}
            else:
                logger.info('Error EventsManager')
                return {'ack': 'false'}
        else:
            logger.info('Error UserProfiling')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Invite Friends')

def leave_group(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'event_id')):
        user_id = body_payload['user_id']
        event_id = body_payload['event_id']
        logger.info('Removing user {} from group {}'.format(user_id, event_id))
        events_manager = requests.delete(SERVICES['EventsManagerService']['DELETE_USER'], params={'user_id': user_id,
                                                                             'event_id': event_id,
                                                                             'access_token': STATE['EventsManagerService'][1]})
        status_code = events_manager.status_code
        if status_code == 200:
            logger.info('User {} has been removed from the group {}.'.format(user_id, event_id))
            chat_room_jid = str(event_id) + '@conference.test'
            nick = 'fabio'
            message_= {'chat_room_jid': chat_room_jid, 
                        'user_nick': nick,
                        'access_token': STATE['ChatManager'][1]
            }
            chat_manager = requests.post(SERVICES['ChatManager']['LEAVE_ROOM'], json=message_)

            status_code = chat_manager.status_code
            if status_code == 200:
                logger.info('User {} has been removed from the group {} - XMPP.'.format(user_id, chat_room_jid))
                return {'ack': 'true'}
            else:
                logger.warning('User not removed')
                return {'ack': 'false'}
            return events_manager.json()
        else:
            logger.warning('User not removed')
            return {'ack': 'false'}
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Leave Group')

def delete_group(body_payload):
    logger.info('Checking request parameters')
    if all(k in list(body_payload.keys()) for k in ('user_id', 'event_id')):
        user_id = body_payload['user_id']
        event_id = body_payload['event_id']
        logger.info('Removing Event {} from group {}'.format(user_id, event_id))
        events_manager = grequests.delete(SERVICES['EventsManagerService']['DELETE_EVENT'], params={'user_id': user_id,
                                                                             'event_id': event_id,
                                                                             'access_token': STATE['EventsManagerService'][1]})
        schedule_manager = grequests.delete(SERVICES['ScheduleManager']['DELETE_ALL'], params={'request_id': event_id,
                                                                                        'access_token': STATE['ScheduleManager'][1]})
        location_manager = grequests.delete(SERVICES['LocationsService']['ADD_EVENT'], params={'event_id': event_id,
                                                                                               'access_token': STATE['LocationsService'][1]})
        alarm_manager = grequests.delete(SERVICES['AlarmManager']['CREATE_ALARM'], params={'id': event_id,
                                                                                'access_token': STATE['AlarmManager'][1]})
        chat_room_jid = str(event_id) + '@conference.test'
        message_= {'chat_room_jid': chat_room_jid, 
                    'access_token': STATE['ChatManager'][1]
        }
        chat_manager = grequests.delete(SERVICES['ChatManager']['REMOVE_GROUP'], params=message_)

        reqs = [events_manager, alarm_manager, schedule_manager, location_manager, chat_manager]
        response = grequests.map(reqs)
        logger.info([True for x in response if x.status_code == 200])
        flag = all([True for x in response if x.status_code == 200])
        if flag:
            logger.info('All processes concluded with success')
            return {'ack': 'true'}
        else:
            logger.info('Failed to delete something related to an event.')
    else:
        logger.warning('Parameters do not fit to the specified for the operation: Delete Group')

def authentication_app(body_payload):
    if request.method == 'POST':
        logger.info('Checking request parameters')
        if all(k in list(body_payload.keys()) for k in ('username', )):
            username = body_payload['username']
            authentication = requests.post(SERVICES['AUTHENTICATION']['POST'], json={'username': username})
            if authentication.status_code == 200:
                logger.info('Authentication Post - Successfully')
            else:
                logger.info('Authentication Post - Unuccessfully')
            return authentication.json()
        else:
            logger.warning('Parameters do not fit to the specified for the operation: Authentication POST')
    if request.method == 'GET':
        logger.info('Checking request parameters')
        data = request.authorization
        for field in ('username', 'password'):
            if field not in list(data.keys()):
                return {'msg' :'{} cannot be blank'.format(field),
                        'ack': 'false'}, 400
        authentication = requests.get(SERVICES['AUTHENTICATION']['GET'], auth=(data['username'], data['password']))
        if authentication.status_code == 200:
            logger.info('Authentication Get - Successfully')
        else:
            logger.info('Authentication Get - Unuccessfully')
            return authentication.json()
    else:
        logger.warning('Invalid method - Authentication')

@app.route('/proxy/<string:method>', methods=['GET', 'POST', 'DELETE'])
@check_authorization('EventsManagerService','FacebookService', 'GeolocationService', 'LocationsService', 'ScheduleManager', 'UserProfilingService','WeatherProxy', 'SmsManagerService', 'PushNotificationService', 'AlarmManager', 'ChatManager')
def proxy(method):
    # content-type = application/json
    body_payload = request.get_json(force=True)
    print(body_payload)
    print(request.args)
    mapping = {'login': login,
               'update_user': update_user,
               'create_event': create_event,
               'update_event': update_event,
               'search': search,
               'add_user': add_user,
               'add_schedule': update_schedule,
               'add_location': add_location,
               'vote_datetime': vote_datetime,
               'get_groups': get_groups,
               'get_group': get_group,
               'vote_local': vote_local,
               'notifications_manager': notifications_manager,
               'invite_friends': invite_friends,
               'leave_group': leave_group,
               'delete_group': delete_group,
               'authentication_app': authentication_app
               }
    to_return = mapping[method](body_payload)
    return json.dumps(to_return)


@app.route('/proxy/internal/<string:method>', methods=['GET', 'POST'])
def internal(method):
    mapping = {'authentication': authentication,
                'get_credentials': get_credentials}
    to_return = mapping[method]()
    return json.dumps(to_return)


@app.route('/proxy/authorizationCallback/', methods=['GET', 'POST'])
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


# TODO IMPLEMENT ON EVERY METHOD CALLED BY OTHERS
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
    logger.info(req.json())
    JWT = req.json()['jwt-bearer']
    return {'jwt': JWT}


def get_credentials():
    reqs = []
    for service in AUTH_SERVICES:
        logger.info(service)
        event = requests.post(SERVICES[service]['GET_APP'],  
            json={'redirect_uri': SERVICES[service]['CALLBACK'], 'scopes': SERVICES[service]['SCOPES'], 'jwt-bearer': JWT})
        reqs.append(event.json())
        CREDENTIALS[service]=event.json()
    logger.info('Done: \n'.join('{}: {}'.format(*k) for k in enumerate(reqs)))
    return {'ack':'True'}
    
paho_client = paho.Client()
paho_client.on_message = on_message    
paho_client.connect(host='172.18.0.33', port=1883)
paho_client.subscribe("chatManager/response")

if __name__ == '__main__':
    bc_thread = Background_Thread()
    bc_thread.start()

    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    config = Configuration(filename='app_server.ini')
    SERVICES = config.service_config
    PENDING_AUTHORIZATION = {}
    AUTH_SERVICES = [x for x in list(SERVICES.keys()) if x not in ('APPSERVER', 'AUTHENTICATION')]
    logger.info('Services to get authorization: \n'.join('{}: {}'.format(*k) for k in enumerate(AUTH_SERVICES)))
    STATE = {k: None for k in AUTH_SERVICES}
    app.run(host='0.0.0.0', port=5012, threaded=True)
