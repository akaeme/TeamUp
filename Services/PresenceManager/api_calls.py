import json
import paho.mqtt.client as mqtt

client = mqtt.Client(client_id="3")
client.connect("localhost", 1883)

tmp = json.dumps({'type':'getPresence', 'chat_room_jid': '1111@conference.deti-es-04.ua.pt'})
#tmp = json.dumps({'type':'leaveChatRoom', 'chat_room_jid': '11211@conference.deti-es-04.ua.pt'})
#tmp = json.dumps({'type':'enterChatRoom', 'chat_room_jid': '1111@conference.deti-es-04.ua.pt'})
	
client.publish("chatManager/requests", tmp)

	