import requests

# EventsManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5002/eventsManager/v1.1/internal/')
print('{:30} - {:>20}'.format('EventsManager ', r.json().__str__()))

# END

# Facebook Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5003/facebook/v1.0/internal/')
print('{:30} - {:>20}'.format('Facebook ', r.json().__str__()))
# END

# Geolocation Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5004/geolocation/v1.0/internal/')
print('{:30} - {:>20}'.format('Geolocation ', r.json().__str__()))
# END

# LocationManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5005/locationManager/v1.1/internal/')
print('{:30} - {:>20}'.format('LocationManager ', r.json().__str__()))
# END

# ScheduleManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5006/scheduleManager/v1.0/internal/')
print('{:30} - {:>20}'.format('ScheduleManager ', r.json().__str__()))
# END

# UserProfiling Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5007/userProfiling/v1.0/internal/')
print('{:30} - {:>20}'.format('UserProfiling ', r.json().__str__()))
# END

# OpenWeather Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5009/Opw/v1.1/internal/')
print('{:30} - {:>20}'.format('OpenWeather ', r.json().__str__()))
# END

# UndergroundWeather Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5010/Underground/v1.1/internal/')
print('{:30} - {:>20}'.format('UndergroundWeather ', r.json().__str__()))
# END

# ChatManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5014/chatManager/v1.0/internal/')
print('{:30} - {:>20}'.format('ChatManager ', r.json().__str__()))
# END

# SmsManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5016/smsManager/v1.1/internal/')
print('{:30} - {:>20}'.format('SmsManager ', r.json().__str__()))
# END

# PushNotifications Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5017/pushNotification/v1.0/internal/')
print('{:30} - {:>20}'.format('PushNotifications ', r.json().__str__()))
# END


# WeatherProxy Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5008/weatherproxy/v1.0/internal/')
r = requests.post('http://192.168.1.100:5008/weatherproxy/v1.0/', json={'hello': 'world'})
r = requests.post('http://192.168.1.100:5008/weatherproxy/v1.0/', json={'hello': 'world'})
print('{:30} - {:>20}'.format('WeatherProxy ', r.json().__str__()))
# END

# AlarmManager Configuration
# BEGIN
r = requests.get('http://192.168.1.100:5001/alarmManager/v1.0/internal/')
r = requests.post('http://192.168.1.100:5001/alarmManager/v1.0/', json={'hello': 'world'})
r = requests.post('http://192.168.1.100:5001/alarmManager/v1.0/', json={'hello': 'world'})
print('{:30} - {:>20}'.format('AlarmManager ', r.json().__str__()))
# END


# App Server Configuration
# BEGIN
r = requests.post('http://192.168.1.100:5012/proxy/internal/authentication', json={'hello': 'world'})
print('{:30} - {:>20}'.format('App Server Authentication ', r.json().__str__()))

r = requests.post('http://192.168.1.100:5012/proxy/internal/get_credentials', json={'hello': 'world'})
print('{:30} - {:>20}'.format('App Server Credentials ', r.json().__str__()))

r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})
r = requests.get('http://192.168.1.100:5012/proxy/get_groups', json={'hello': 'world'})

# END
