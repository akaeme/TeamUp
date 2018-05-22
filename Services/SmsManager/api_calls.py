import requests

r = requests.post('http://127.0.0.1:5015/smsManager/v1.1/sendMessage/', json={'mobile_nr_list': ['969857311', '969857311'], 'message': 'Hi from TeamUp!'}, params={})

print(r.content)