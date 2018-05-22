import requests
# First request
'''
r = requests.post('http://deti-es-04.ua.pt3:5013/v1.0/authentication/', json={'username': 'app'})
print(r.json())
'''
# Second
'''
r = requests.get('http://deti-es-04.ua.pt3:5013/v1.0/authentication/get_token', auth=('app', 'test'))
print(r.json())
'''
# Validate
'''
r = requests.get('http://deti-es-04.ua.pt3:5013/v1.0/authentication/validate', headers={'Authorization':'Bearer ' + 'a'}, params={'jwt': 'a'})
print(r.json())
'''
