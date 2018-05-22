import requests
#Create
'''
r = requests.post('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/create', json={'name': 'eventName',
                                                                                  'type': 0,
                                                                                  'activity': 'football',
                                                                                  'maxppl': 20,
                                                                                  'minppl': 10,
                                                                                  'owner': 1234,
                                                                                  'description': 'event description',
                                                                                  'access_token': 'fm5XmtmnSTWscdurORbIkpNVgLiCRN'})
'''
# Update
'''
r = requests.post('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/update', json={'user_id': 1234,
                                                                                  'event_id': 2,
                                                                                  'name': 'eventNewName',
                                                                                  'type': 0,
                                                                                  'activity': 'basket',
                                                                                  'maxppl': 20,
                                                                                  'minppl': 10,
                                                                                  'description': 'event update',
                                                                                  'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Public Events
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'op_type': 'publicEvents',
                                                                              'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Participants
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'op_type': 'participants',
                                                                              'event_id': 2,
                                                                              'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Public by Activity
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'op_type': 'publicByActivity',
                                                                              'activity': 'basket',
                                                                              'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Event Name
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'op_type': 'eventName',
                                                                                'event_id': 2,
                                                                                'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Event Information
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'op_type': 'event_info',
                                                                                'event_id': 2,
                                                                                'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Get User Events
'''
r = requests.get('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/users/', params={'user_id': 1234, 
                                                                              'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Add user
'''
r = requests.post('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/users/', json={'event_id': 2,
                                                                              'user_id': 9876,
                                                                              'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Delete User
'''
r = requests.delete('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/users/', params={'event_id': 2, 
                                                                                  'user_id': 9876,
                                                                                  'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
# Delete Event
'''
r = requests.delete('http://deti-es-04.ua.pt3:5002/eventsManager/v1.1/events/', params={'event_id': 2, 'user_id': 1234,
                                                                                   'access_token': '7uv1pOJDA69MvANEf3e6TcP102HcMy'})
'''
print(r.json())