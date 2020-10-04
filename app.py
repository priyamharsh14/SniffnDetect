import time
import asyncio
from sniffndetect import *
from quart import Quart, websocket, request, render_template

app = Quart(__name__)
connected_WS = None
sniffer = SniffnDetect()

@app.route('/', methods=['GET'])
async def index():
    global sniffer
    return await render_template('homepage.html', config=[sniffer.INTERFACE, sniffer.MY_IP, sniffer.MY_MAC])

@app.websocket('/ws')
async def ws():
    global connected_WS
    try:
        if not connected_WS:
            connected_WS = websocket
        else:
            return "Already connect to WS", 400
    except asyncio.CancelledError:
        connected_WS = None
        sniffer.stop()
        raise

if not is_admin():
    sys.exit("[-] Please execute the script with root or administrator priviledges.\n[-] Exiting.")
else:
    app.run()