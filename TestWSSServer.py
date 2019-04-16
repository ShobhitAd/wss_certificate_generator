#!/usr/bin/env python3

# WSS (WS over TLS) server example, with self signed certificate

import asyncio
import pathlib
import ssl
import websockets
import socket

ws_settings = {
    "ip" : '',
    "port" : '8080',
    "key_file" : 'privatekey.key',
    "cert_file" : 'cert.pem',
    "cert_path" : ''
}

def getIP():
  test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  test_socket.connect(("8.8.8.8", 80))
  return test_socket.getsockname()[0]

if ws_settings["ip"] == '':
  print('No ip address specified. Getting ip from system')
  ws_settings["ip"] = getIP()

print("Start WSS server: wss://%s:%s/" % (ws_settings["ip"], ws_settings["port"]))
print(ssl.OPENSSL_VERSION)

async def hello(websocket, path):
    name = await websocket.recv()
    print(name)

    greeting = "Hello %s" % name

    await websocket.send(greeting)
    print(greeting)

    if name == 'exit':
        exit(0)

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

ssl_context.load_cert_chain(
    (ws_settings["cert_path"] + ws_settings["cert_file"]), (ws_settings["cert_path"] + ws_settings["key_file"])
)
start_server = websockets.serve(hello, ws_settings["ip"], ws_settings["port"], ssl = ssl_context)


asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
