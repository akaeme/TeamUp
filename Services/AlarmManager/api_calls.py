import requests
'''
r = requests.post('http://deti-es-04.ua.pt3:5001/alarmManager/v1.0/', json={'datetime': '23:38 02/01/2018',
                                                                   'id': '7',
                                                                   'access_token': 'qcgPIJni9X16kTWESoVnFa2QxqvhTl'})
'''

r = requests.delete('http://deti-es-04.ua.pt3:5001/alarmManager/v1.0/', params={'id': '7',
                                                                   'access_token': 'qcgPIJni9X16kTWESoVnFa2QxqvhTl'})

print(r.json())

