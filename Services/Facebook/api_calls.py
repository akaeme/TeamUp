import requests

'''r = requests.post('http://127.0.0.1:5004/facebook/v1.0',
                  json={"access_token": "EAACEdEose0cBAFDJCTTThK9CqruRAJ2Ef3TgI8sTUAp5jXKmFawwoJ7ULbdUg9yXgRYqd9ic0ZBYW7kCqgZAnTbgaL8yUTf9QRZBp5rTAc3FxNAekZCEdnSZCdp66BBbYD8Vtd6gAuZCnTqZBDd5zaO6JvyZBjyZBkSnYUSy2bSlvTJXRZAGmAZAYp6Cx4uAw3xoJZChOwZCcGKP7TwZDZD",
                        "id":"682109031847376",
                        "expires_in": 6666})

r = requests.get('http://127.0.0.1:5004/facebook/v1.0',
                  json={"id":"682109031847376"})
r = requests.delete('http://127.0.0.1:5004/facebook/v1.0',
                  params={"id":"682109031847376"})
print(r.json())'''

# GET
r = requests.get('http://127.0.0.1:5003/facebook/v1.0/', params={'access_token': 'helloworld', 'id': '4'})
# POST
r = requests.post('http://127.0.0.1:5003/facebook/v1.0/', json={"access_token": "EAACE...NQZDZD", "id":"4", "expires_in": 3600,
        'access_token_': 'helloworld'})
# DELETE
r = requests.delete('http://127.0.0.1:5003/facebook/v1.0/', params={'access_token': 'helloworld', id='4'})
print(r.json())
#1588088727916064
#682109031847376