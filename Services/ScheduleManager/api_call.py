import requests

r = requests.get('http://192.168.1.3:5006/scheduleManager/v1.0/schedule/', json={'request_id': 8})
#r = requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postRequest', json={'request_id': 125, 'timestamp': 1510238506})
#r = requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/postSchedule', json={'request_id': 123, 'timestamp': 1510238888,
#                                                                                            'priority': 7})
#r = requests.delete('http://127.0.0.1:5006/scheduleManager/v1.0/schedule/', json={'request_id': 123, 'timestamp': 1510238506})

#r = requests.get('http://127.0.0.1:5006/scheduleManager/v1.0/voting/', json={'request_id': 123})
#r = requests.post('http://127.0.0.1:5006/scheduleManager/v1.0/voting/', json={'request_id': 123, 'timestamp': 1510238777})

print (r.content)