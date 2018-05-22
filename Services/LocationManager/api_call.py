import requests

# EventLocation
# get all locations
#r = requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/all_locations', json={'event_id': 3})
# get most voted
#r = requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/most_voted', json={'event_id': 3})
# get three most voted
r = requests.get('http://127.0.0.1:5005/locationManager/v1.1/voting/three_most_voted', json={'zone': 'Aveiro'})
# add event
#r = requests.post('http://127.0.0.1:5005/locationManager/v1.1/Event_location/', json={'event_id': 3,
#                                                                                      'timestamp': 1511046742})

# VOTING
# add location
#r = requests.post('http://127.0.0.1:5005/locationManager/v1.1/voting/add_location', json={'event_id': 3,
#                                                                                          'lat': '40,6303',
#                                                                                          'long': '-7,6575',
#                                                                                          'city': 'Aveiro',
#                                                                                          'priority': 2})

# vote location
#r = requests.post('http://127.0.0.1:5005/locationManager/v1.1/voting/vote', json={'event_id': 3,
#                                                                                  'lat': '40,6303',
#                                                                                  'long': '-7,6575'})
'''
# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/voting/', json={'event_id':3})
# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/location/getLocations')
# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/location/getCoords', json={'location_id':4})
'''

r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/location/', json={'location_id':4})
r = requests.delete('http://127.0.0.1:5005/locationManager/v1.0/location/', json={'location_id':4})
#EventLocations

'''
# Voting
# r = requests.post('http://127.0.0.1:5005/locationManager/v1.0/voting/', json={"event_id":"3",
#                                                                     "location_id": "4",
#                                                                     "vote": "10"})

# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/voting/', json={'event_id': 1})

# r = requests.post('http://127.0.0.1:5005/locationManager/v1.0/location/', json={"name": "Universidade Catolica",
#                                                                                       "lat": "37,883",
#                                                                                      "long": "-4,123",
#                                                                                     "city": "Porto"})

# r = requests.post('http://127.0.0.1:5005/locationManager/v1.0/Event_location/', json={'event_id': 4,
#                                                                             'timestamp': 1511803800})

# r = requests.post('http://127.0.0.1:5005/locationManager/v1.0/voting/', json={"event_id":"4",
#                                                                              "lat":"33,883",
#                                                                              "long":"-2,12"})


# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/voting/getVotedLocationByID',json={"event_id":"4"})
# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/voting/getVotedLocations',json={"city":"Aveiro"})
# r = requests.get('http://127.0.0.1:5005/locationManager/v1.0/voting/getVotedLocations')
'''

print(r.json())
