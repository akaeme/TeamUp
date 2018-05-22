import requests

#createUser
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/createUser', json={'username': 1112, 'password': 'xxxx'})
print(r.json())'''

#crateGroup
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/createAndConfigureChatRoom', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'room_name': 'TeamUp', 'room_desc': 'My room description', 'logging':1, 'invite':1, 'allow_pm':'anyone', 'max_users': 50, 'public_room': 1, 'persistent_room': 1,'moderated_room': 0, 'members_only': 0, 'disc_JID':'moderators'})
print(r.json())'''

#sendInvite
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/sendInvite', json={'user_jid': '1112@deti-es-04.ua.pt/Ruis-MacBook-Pro','chat_room_jid': '50@conference.deti-es-04.ua.pt'})
print(r.json())
'''

#sendGroupChatMessage
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/sendMessage', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'message':'heeey'})
print(r.json())'''


#removeGroup
'''
r = requests.delete('http://127.0.0.1:5014/chatManager/v1.0/', params={'chat_room_jid': '50@conference.deti-es-04.ua.pt'})
print(r.json())'''

#addMember
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/addMember', json={'chat_room_jid': '50@conference.deti-es-04.ua.pt', 'user_jid':'1112@deti-es-04.ua.pt'})
print(r.json())
'''

#leaveChatRoom
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/removeMember', json={'chat_room_jid': '60@conference.deti-es-04.ua.pt', 'nick':'rui', 'role':'none'})
print(r.json())'''


#setAffiliation
'''
r = requests.post('http://127.0.0.1:5014/chatManager/v1.0/setAffiliation', json={'chat_room_jid': '60@conference.deti-es-04.ua.pt', 'user_jid':'fabio@deti-es-04.ua.pt/mynick', 'affiliation':'outcast', 'access_token':'hello_world'})
print(r.json())'''








