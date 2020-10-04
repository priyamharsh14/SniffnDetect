import time
import asyncio
from sniffndetect import *
from datetime import datetime
from quart import Quart, websocket, request, render_template

app = Quart(__name__)
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
        return {'status': 200, 'message': f'Started Sniffer @ {str(datetime.now()).split(".")[0]}'}

@app.route('/api/v1/stop', methods=['GET'])
async def stop_sniffer():
    if sniffer.flag:
        sniffer.stop()
        return {'status': 200, 'message': f'Stopped Sniffer @ {str(datetime.now()).split(".")[0]}'}
    else:
        return {'status': 404, 'message': 'Already Stopped'}

@app.websocket('/ws')
async def ws():
    global sniffer
    try:
        if not sniffer.WEBSOCKET:
            sniffer.WEBSOCKET = websocket
            await websocket.accept()
        else:
            return "Already connect to WS", 400
    except asyncio.CancelledError:
        sniffer.WEBSOCKET = None
        sniffer.stop()
        raise

if not is_admin():
    sys.exit("[-] Please execute the script with root or administrator priviledges.\n[-] Exiting.")
else:
    app.run()