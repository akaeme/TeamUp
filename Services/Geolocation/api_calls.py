import requests

# User Position
'''
r = requests.post('http://deti-es-04.ua.pt3:5004/geolocation/v1.0/', json={'user_id': '1234',
                                                                  'lat': '2.0',
                                                                  'lng': '2.0',
                                                                  'access_token': '5xUUYUOcBrr8cy2d1USTO9mlJxQRPL'})
'''              
# Geocode
'''                                                    
r = requests.get('http://deti-es-04.ua.pt3:5004/geolocation/v1.0/geocode', params={'address': 'Porto',
																			'access_token': '5xUUYUOcBrr8cy2d1USTO9mlJxQRPL'})
'''
# Position
'''
r = requests.get('http://deti-es-04.ua.pt3:5004/geolocation/v1.0/position', params={'user_id': '1234',
																			'access_token': '5xUUYUOcBrr8cy2d1USTO9mlJxQRPL'})
'''
# Look Up
'''
r = requests.get('http://deti-es-04.ua.pt3:5004/geolocation/v1.0/lookup', params={'lat': '40.640506',
                                                                        'lng': '-8.653754',
                                                                        'access_token': '5xUUYUOcBrr8cy2d1USTO9mlJxQRPL'})
'''
# Delete User
'''
r = requests.delete('http://deti-es-04.ua.pt3:5004/geolocation/v1.0/', params={'user_id': '1234',
																		'access_token': '5xUUYUOcBrr8cy2d1USTO9mlJxQRPL'})
'''																		
print(r.json())