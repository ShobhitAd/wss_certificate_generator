#!/usr/bin/env python3

# WSS (WS over TLS) client example, with a self-signed certificate

import asyncio
import pathlib
import ssl
import websockets
import socket

ws_settings = {
    "ip" : '',
    "port" : '8080',
    "cert_file" : 'CAcert.pem',
    "cert_path" : ''
}

def getIP():
  test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  test_socket.connect(("8.8.8.8", 80))
  return test_socket.getsockname()[0]

if ws_settings["ip"] == '':
  print('No ip address specified. Getting ip from system')
  ws_settings["ip"] = getIP()

print("Start WSS client: wss://%s:%s/" % (ws_settings["ip"], ws_settings["port"]))
print(ssl.OPENSSL_VERSION)

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations(ws_settings["cert_path"] + ws_settings["cert_file"])

async def hello():
    async with websockets.connect(
            'wss://%s:%s' % (ws_settings["ip"], ws_settings["port"]), ssl=ssl_context) as websocket:

        name = input("What's your name? ")

        await websocket.send(name)
        print(f"> {name}")

        greeting = await websocket.recv()
        print(f"< {greeting}")

        if name == 'exit':
            exit(0)

while True:
    asyncio.get_event_loop().run_until_complete(hello())
