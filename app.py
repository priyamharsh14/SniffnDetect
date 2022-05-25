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
    return await render_template(
        'homepage.html',
        config=[sniffer.INTERFACE, sniffer.MY_IP, sniffer.MY_MAC],
        flags=sniffer.FILTERED_ACTIVITIES
    )

async def WS_receiver():
    global sniffer
    while sniffer.WEBSOCKET is not None:
        data = await sniffer.WEBSOCKET.receive()
        if data == 'CMD::START':
            if sniffer.flag:
                await sniffer.WEBSOCKET.send('LOG::Already Running')
            else:
                await sniffer.WEBSOCKET.send(f'LOG::Started Sniffer @ {str(datetime.now()).split(".")[0]}')
                sniffer.start()
        elif data == 'CMD::STOP':
            if sniffer.flag:
                await sniffer.WEBSOCKET.send(f'LOG::Stopped Sniffer @ {str(datetime.now()).split(".")[0]}')
                sniffer.stop()
            else:
                await sniffer.WEBSOCKET.send('LOG::Already Stopped')
        elif data == 'CMD::FATTACKERS':
            if any([sniffer.FILTERED_ACTIVITIES[category]['flag'] for category in sniffer.FILTERED_ACTIVITIES]):
                await sniffer.WEBSOCKET.send(f"FA0::{sniffer.find_attackers('TCP-SYN')}{sniffer.find_attackers('TCP-SYNACK')}{sniffer.find_attackers('ICMP-POD')}{sniffer.find_attackers('ICMP-SMURF')}")
            else:
                await sniffer.WEBSOCKET.send('FA0::No DDOS attack detected yet. Try again later.')
        else:
            await sniffer.WEBSOCKET.send('LOG::Invalid CMD')

async def WS_sender():
    global sniffer
    while sniffer.WEBSOCKET is not None:
        if sniffer.RECENT_ACTIVITIES:
            data = []
            for pkt in sniffer.RECENT_ACTIVITIES[::-1]:
                msg = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt[0]))} <{'|'.join(pkt[1])}> {pkt[2]}:{pkt[6]} ({pkt[4]}) => {pkt[3]}:{pkt[7]} ({pkt[5]})"
                if pkt[8]:
                    msg += f" [{pkt[8]} bytes]"
                if pkt[9]:
                    msg += f" <{pkt[9]}>"
                data.append(msg)
            await sniffer.WEBSOCKET.send("PKT::"+"\n".join(data))
        await sniffer.WEBSOCKET.send(f"FLAG:{sniffer.FILTERED_ACTIVITIES['TCP-SYN']['flag']},{sniffer.FILTERED_ACTIVITIES['TCP-SYNACK']['flag']},{sniffer.FILTERED_ACTIVITIES['ICMP-POD']['flag']},{sniffer.FILTERED_ACTIVITIES['ICMP-SMURF']['flag']}")

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
