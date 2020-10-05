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

async def WS_receiver():
	global sniffer
	while sniffer.WEBSOCKET is not None:
		data = await sniffer.WEBSOCKET.receive()
		if data == 'CMD::START':
			if sniffer.flag:
				await sniffer.WEBSOCKET.send('LOG::Already Started')
			else:
				sniffer.start()
				await sniffer.WEBSOCKET.send(f'LOG::Started Sniffer @ {str(datetime.now()).split(".")[0]}')
		elif data == 'CMD::STOP':
			if sniffer.flag:
				await sniffer.WEBSOCKET.send(f'LOG::Stopped Sniffer @ {str(datetime.now()).split(".")[0]}')
				sniffer.stop()
			else:
				await sniffer.WEBSOCKET.send('LOG::Already Stopped')
		else:
			await sniffer.WEBSOCKET.send('LOG::Invalid CMD')

async def WS_sender():
	global sniffer
	while sniffer.WEBSOCKET is not None:
		await sniffer.WEBSOCKET.send("\n".join([f"{pkt}" for pkt in sniffer.RECENT_ACTIVITIES[::-1]]))

@app.websocket('/ws')
async def ws():
	global sniffer
	try:
		if not sniffer.WEBSOCKET:
			sniffer.WEBSOCKET = websocket
			await websocket.accept()
		else:
			return "Already connect to WS", 400
		producer = asyncio.create_task(WS_sender())
		consumer = asyncio.create_task(WS_receiver())
		await asyncio.gather(producer, consumer)
	except asyncio.CancelledError:
		sniffer.WEBSOCKET = None
		sniffer.stop()
		raise

if not is_admin():
	sys.exit("[-] Please execute the script with root or administrator priviledges.\n[-] Exiting.")
else:
	try:
		app.run()
	except KeyboardInterrupt:
		sys.exit("[-] Ctrl + C triggered.\n[-] Shutting Down")