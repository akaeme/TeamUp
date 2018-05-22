import requests

r = requests.post('http://127.0.0.1:5017/pushNotification/v1.0/sendNotification/', json={'topic': 'test2', 'message': 'teamup rullzzz'})

print(r.json())