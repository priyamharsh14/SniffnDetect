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
    return await render_template('homepage.html', config=[sniffer.INTERFACE.name, sniffer.MY_IP, sniffer.MY_MAC])

@app.route('/api/v1/start', methods=['GET'])
async def start_sniffer():
    if sniffer.flag:
        return {'status': 404, 'message': 'Already Running'}
    else:
        sniffer.start()
        return {'status': 200, 'message': 'Started Sniffer'}

@app.route('/api/v1/stop', methods=['GET'])
async def stop_sniffer():
    if sniffer.flag:
        sniffer.stop()
        print(sniffer.RECENT_ACTIVITIES)
        return {'status': 200, 'message': 'Stopped Sniffer'}
    else:
        return {'status': 404, 'message': 'Already Stopped'}

@app.websocket('/ws')
async def ws():
    global connected_WS
    try:
        if not connected_WS:
            connected_WS = websocket
            await websocket.accept()
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