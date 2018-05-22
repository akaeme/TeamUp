import requests
r = requests.post('http://192.168.1.14:5009/Opw/', json={
        'day': '13',
        'hour': '11',
        'lat': '40.6391851',
        'long': '-8.6545585'
    })

#r = requests.post('http://127.0.0.1:5008/alarmWeather/v1.0', json={'datetime': '11:00 16/11/2017',
#                                                                   'lat': '40.63036952784689',
#                                                                   'long': '-8.657569885253906',
#                                                                   'id': '1'})

#r = requests.get('http://127.0.0.1:5008/alarmWeather/v1.0/AlarmW')
#r = requests.get('http://127.0.0.1:5020/alarmWeather/v1.0/AlarmW_ID', json = {'event_id':1})

print(r.json())



