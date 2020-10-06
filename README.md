<h1 align="center">SniffnDetect 2.0</h1>

## What is SniffnDetect 2.0 ?

SniffnDetect 2.0 is an advanced DDOS detector tool written in Python3. It will sniff all the traffic in your network and identify attacks like:

- SYN Flood Attack
- SYN-ACK Flood Attack
- ICMP Smurf Attack
- Ping of Death

After detecting those attack(s), it will also try to find the source of the attack and provide the details of the attacker(s). This version of SniffnDetect has been heavily optimized and by utilizing threads, Quart framework, and WebSockets, it also provides a beautiful Web User Interface for the user.

## Upcoming Features

- More attack detection algorithms
- Defense mechanisms to counteract DDOS attacks (LINUX only)
- Better animations and transitions in Web UI

## Installation
```
$ git clone https://github.com/priyamharsh14/SniffnDetect.git
$ cd SniffnDetect
/SniffnDetect/$ pip install -r requirements.txt
```

## Usage

NOTE: Script must run in root (in Linux) or Administrator (in Windows)
```
/SniffnDetect/$ sudo python3 app.py
```
This will start the web interface at your local port 5000. Now, you can simply fire up your browser and go to 127.0.0.1:5000 to access it.
