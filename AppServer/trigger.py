import requests



'''
# Login
r = requests.post('https://qnvjfrtgaf.localtunnel.me/proxy/login', json={'user_id':'758941187514413',
                                                             'access_token': 'EAACEdEose0cBAJU7crBppbHCaMXQUZC3sXmy6ue1RAUayccMMa4borJDjS0zcLbs2dKiHA62AzE3NJ0cRNjk3ZBuhtQTM6TqDnJZCWUF26tZAZCKUtB60e3hPMOVwBmqIkhDYHVnLZA3ZACeKBzftkMJn9vJ85hnjZAz8dj62DkfKHnJ3ox3xHmKwxuzWFkZCB8Hst1e6kZCk7CQZDZD',
                                                             'expires_in': 6666})
print(r.content)

'''
# Create Event

'''
r = requests.post('http://192.168.43.100:5012/proxy/create_event', json={'name': 'menito',
                                                                    'type': 0,
                                                                    'activity': 'futebol',
                                                                    'maxppl': 20,
                                                                    'minppl': 10,
                                                                    'owner': 1234,
                                                                    'description': 'Lets get it man.',
                                                                    'locations': [['40.6718599', '-7.9047571'], ['40.6715311', '-7.9115649']],
                                                                    'locations_priority': [10,20],
                                                                    'schedules': [' 1515167577', '1515253977'],
                                                                    'schedules_priority': [10,20],
                                                                    'decision': '23:50 04/01/2018'})
print(r.json())
'''

'''
r = requests.post('http://192.168.1.5:5012/proxy/create_event', json={'name': 'eventName',
                                                                    'type': 0,
                                                                    'activity': 'basket',
                                                                    'maxppl': 20,
                                                                    'minppl': 10,
                                                                    'owner': 1234,
                                                                    'description': 'event description',
                                                                    'locations': [['40.635955', '-8.686495'], ['40.645106', ' -8.662097']],
                                                                    'locations_priority': [10,20],
                                                                    'schedules': [' 1513978958', '1513982558'],
                                                                    'schedules_priority': [10,20],
                                                                    'decision': '12:00 23/11/2017'})



r = requests.post('http://192.168.1.5:5012/proxy/create_event', json={'name': 'eventName',
                                                                    'type': 0,
                                                                    'activity': 'basket',
                                                                    'maxppl': 20,
                                                                    'minppl': 10,
                                                                    'owner': 1234,
                                                                    'description': 'event description',
                                                                    'locations': [['41.157944', '-8.629105'], ['41.158883', ' -8.630705']],
                                                                    'locations_priority': [10,20],
                                                                    'schedules': [' 1513251203', '1513982558'],
                                                                    'schedules_priority': [10,20],
                                                                    'decision': '12:00 23/11/2017'})
'''
# Update Event
'''r = requests.post('http://127.0.0.1:5012/proxy/update_event', json={'user_id': '1234',
                                                                    'event_id': 14,
                                                                    'name': 'newnew',
                                                                    'type': 0,
                                                                    'activity': 'basket',
                                                                    'maxppl': 20,
                                                                    'minppl': 10,
                                                                    'description': 'event update',
                                                                    'atmppl': 5})'''
# Update Profile
'''
r = requests.post('http://127.0.0.1:5012/proxy/update_user', json={'user_id': '682109031847376',
                                                                   'username': 'Rui',
                                                                   'tlm': '969999999'})'''
# Add user to event
'''
r = requests.post('http://192.168.43.1003:5012/proxy/add_user', json={'user_id': '9876',
                                                                'event_id': 11})
'''
# Remove user from event
'''
r = requests.post('http://192.168.43.1003:5012/proxy/leave_group', json={'user_id': '9876',
                                                                'event_id': 11})
'''
# Add schedule
'''r = requests.post('http://127.0.0.1:5012/proxy/add_schedule', json={'timestamp': '17:00 30/11/2017',
                                                                    'event_id': 5})'''
# Vote schedule
'''r = requests.post('http://127.0.0.1:5012/proxy/vote_datetime', json={'timestamp': '17:00 30/11/2017',
                                                                    'event_id': 5})'''
# get groups
#r = requests.get('http://192.168.43.1003:5012/proxy/get_groups', json={'user_id':1234})
# get group
#r = requests.get('http://192.168.1.4:5012/proxy/get_group', json={'event_id': 1})
# search

'''r = requests.get('http://172.18.0.24:5012/proxy/search', json={'user_id': '1234',
                                                             'lat': '40.633774',
                                                             'long': '-8.646869',
                                                             'activity': '',
                                                             'zone': 'Aveiro',
                                                             'distance': 10})
print(r.json())'''
# vote local
'''r = requests.post('http://127.0.0.1:5012/proxy/vote_local', json={'event_id': 7,
                                                                  'lat': '40.6303',
                                                                  'long': '-8.6575'})'''

# add_location
'''r = requests.post('http://192.168.1.3:5012/proxy/add_location', json={'event_id': 6,
                                                                    'lat': '40.640506',
                                                                    'long': '-8.653754',
                                                                    'city': 'Aveiro',
                                                                    'priority': 5})'''
# notification_manager
# decision
'''
r = requests.post('http://192.168.43.100:5012/proxy/notifications_manager', json={'type': 'decision',
                                                                                'event_id': 2})
'''
# weather

r = requests.post('http://192.168.43.100:5012/proxy/notifications_manager', json={'type': 'weather',
                                                                                'event_id': 2,
                                                                                'message': 'Weather Change '})


#reminder

'''
r = requests.post('http://192.168.43.100:5012/proxy/notifications_manager', json={'type': 'reminder',
                                                                                'event_id': 2})
'''
#closeEvent

'''
r = requests.post('http://192.168.43.100:5012/proxy/notifications_manager', json={'type': 'closed_event',
                                                                                'event_id': 2})
'''
# invite friends
'''
r = requests.post('http://192.168.43.1003:5012/proxy/invite_friends', json={'user_id': 1234,
                                                                         'event_id': 21})
'''

# delete_group
'''
r = requests.delete('http://192.168.43.1003:5012/proxy/delete_group', json={'user_id': 1234,
                                                                         'event_id': 29})
'''
# leave group
'''
r = requests.post('http://192.168.43.1003:5012/proxy/leave_group', json={'user_id': 1234,
                                                                         'event_id': 1})

'''
print(r.json())
