import asyncio
import socket
import argparse
import logging
import subprocess
import datetime
import re
import time
import signal
import os
import sys

logger = logging.getLogger(__name__)

STOP=False

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    STOP=True


class HTTPProtocol(asyncio.Protocol):
    def __init__(self, message, on_con_lost, index):
        self.message = f"GET /{message} HTTP/1.1\r\nHost: {HOSTNAME}\r\n\r\n"
        self.on_con_lost = on_con_lost
        self.count = 0
        self.received = b""
        self.index = index

    def connection_made(self, transport):
        HTTPProtocol.SENT_REQUESTS = HTTPProtocol.SENT_REQUESTS + 1
        transport.write(self.message.encode())
        self.transport = transport
        logging.debug(f"{self.index=} Data sent: {self.message!r}")

    def data_received(self, data):
        asyncio.ensure_future(self.process_data(data))

    async def process_data(self, data):
        if STOP:
            self.transport.close()
            return

        self.received = self.received + data
        if b"\r\n\r\n" in self.received:
            logging.debug(f"{self.index=} Data received {self.count=} {self.received!r}")
            self.received = b""
            self.count = self.count + 1
            if self.count == N :
                self.transport.close()
                return

            while (time.time() - START_TIME) * R < HTTPProtocol.SENT_REQUESTS:
                await asyncio.sleep(0.01)

            HTTPProtocol.SENT_REQUESTS = HTTPProtocol.SENT_REQUESTS + 1
            self.transport.write(self.message.encode())

    def connection_lost(self, exc):
        logging.debug(f"{self.index=} connection closed")
        self.on_con_lost.set_result(True)

PORT_OFFSET=40000

async def run(loop, index):
    cur_rate = HTTPProtocol.SENT_REQUESTS / (time.time() - START_TIME) 

    if index % 10 == 0:
        logging.info(f"Starting connection {index} ({cur_rate:.2f} requests per second)")
    else:
        logging.debug(f"Starting connection {index} ({cur_rate:.2f} requests per second)")

    on_con_lost = loop.create_future()
    message = 'A' * L

    global PORT_OFFSET

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', PORT_OFFSET + (index % 20000)))
            break
        except OSError:
            PORT_OFFSET = PORT_OFFSET + 1

    sock.connect((IP, PORT))

    transport, protocol = await loop.create_connection(
        lambda: HTTPProtocol(message, on_con_lost, index),
        sock=sock)
    try:
        await asyncio.wait_for(on_con_lost, timeout=((N / R) + 5))
    finally:
        transport.close()

async def main(loop):
    for x in range(int(C / P) + 1):
        if STOP:
            break
        tasks = [run(loop, x*P+i) for i in range(min(P, C - x*P))]
        try:
            result = await asyncio.gather(*tasks, return_exceptions=IGNORE_ERRORS)
        except Exception as e:
            logging.critical(e, exc_info=True)
            return
        logging.debug(result)

def verify_http():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IP, PORT))
    message = 'A' * L
    request = f"GET /{message} HTTP/1.1\r\nHost: {HOSTNAME}\r\nConnection: keep-alive\r\n\r\n".encode()
    logging.debug(f"verify_http sending {request=}")
    sock.send(request)
    response = b""
    while not b"\r\n\r\n" in response:
        response = response + sock.recv(4096)
    logging.debug(f"verify_http received {response=}")
    assert message.encode() in response, "This script expects the AAAA to be returned in the HTTP response"
    assert not b"@" in response, "This script expects no @ in the HTTP response"
    assert b"\r\nConnection: keep-alive\r\n" in response, "This script expects the connection to be kept alive"
    sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                        prog='Bitflipper',
                        description='Check your connection for bitflips in packets')

    parser.add_argument('-C', '--connections', default=1000, type=int, help="Total number of TCP connections to use, with unique source ports (1-10000)")     
    parser.add_argument('-P', '--parallel', default=5, type=int, help="Number of parallel TCP connections to use, this does not effect the total number of TCP connections to use (1-25)")
    parser.add_argument('-N', '--num-requests', default=10, type=int, help="Number of HTTP requests to send per TCP connection (1-1000)")
    parser.add_argument('-L', '--length', default=3500, type=int, help="Number of A's to use in the request")
    parser.add_argument('-R', '--rate', default=10, type=float, help="Number of HTTP requests per second")
    parser.add_argument('-p', '--port', default=80, type=int, help="TCP Port")
    parser.add_argument('-v', '--verbose', help="enable debugging", action='store_true', required=False, default=False)
    parser.add_argument('-i', '--ignore-errors', help="do not stop when a connection error occurs (most likely due to bitflips)", action='store_true', required=False, default=False)
    parser.add_argument('-q', '--quiet', help="do not show live tshark bitflips", action='store_true', required=False, default=False)
    parser.add_argument('ip', help="IP-address to send HTTP requests to")
    parser.add_argument('hostname', help="Hostname to put in the HTTP request-body")

    args = parser.parse_args()

    C = args.connections
    P = args.parallel
    N = args.num_requests
    L = args.length
    R = args.rate
    IP = args.ip
    PORT = args.port
    QUIET = args.quiet
    IGNORE_ERRORS = args.ignore_errors
    HOSTNAME = args.hostname
    WHEN = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    PCAP=f"bitflipper_{IP}_{HOSTNAME}_{WHEN}.pcap"
    REPORT=f"bitflipper_{IP}_{HOSTNAME}_{WHEN}.txt"

    assert C >= 1 and C <= 10000, "Connections must be between 1 and 10000"
    assert P >= 1 and P <= 25, "Parallel connections must be between 1 and 25"
    assert N >= 1 and N <= 1000, "Number of HTTP requests per connection must be between 1 and 1000"
    assert L >= 1 and L <= 10000, "Number of A's must be between 1 and 10000"

    output = subprocess.check_output(["ip", "-4", "route", "show", "default"]).decode()
    OUTGOING_INTERFACE=re.search("dev ([^ ]+)", output).group(1)

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    logging.info(f"Testing with {C=} {P=} {N=} {L=} {R=} {IP=} {HOSTNAME=} {PCAP=} {REPORT=} {OUTGOING_INTERFACE=} {IGNORE_ERRORS=} {QUIET=}")

    verify_http()


    process_pcap = subprocess.Popen(["tcpdump", "-i", OUTGOING_INTERFACE, "-s", "0", "-w", PCAP, "-U", f"host {IP} and port {PORT}"])
    time.sleep(1)

    if not QUIET:
        print("starting tshark")
        tshark_pcap = subprocess.Popen(f"tail -c +1 -f {PCAP} | tshark -n -x -r - -Y 'tcp.payload contains \"@\"' -x", shell=True, start_new_session=True)
        time.sleep(1)

    HTTPProtocol.SENT_REQUESTS=0
    START_TIME=time.time()
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main(loop))
    except KeyboardInterrupt:
        print("Interrupted!")

    time.sleep(1)
    process_pcap.terminate()
    time.sleep(2)
    if process_pcap.poll() is None:
        process_pcap.kill()
    if not QUIET:
        pgrp = os.getpgid(tshark_pcap.pid)
        os.killpg(pgrp, signal.SIGINT)
        time.sleep(2)
        tshark_pcap.wait()

    print("Generating statistics\n\n")

    SP_TOTAL=set()
    SP_BF=set()
    SP_BF_F=0
    RX_TOTAL=0
    RX_BF=0
    RX_BF_F=0
    RX_SP_BF=0
    TX_TOTAL=0
    p = subprocess.run(["tshark", "-n", "-r", PCAP, "-Y", f"ip.src == {IP} and tcp.srcport == {PORT} and tcp.payload contains \"A\"", "-T", "fields", "-e", "tcp.stream", "-e", "tcp.dstport", "-e", "frame"], capture_output=True, encoding="utf8")
    for line in p.stdout.splitlines():
        RX_TOTAL = RX_TOTAL + 1
    p = subprocess.run(["tshark", "-n", "-r", PCAP, "-Y", f"ip.src == {IP} and tcp.srcport == {PORT} and tcp.payload contains \"@\"", "-T", "fields", "-e", "tcp.stream", "-e", "tcp.dstport", "-e", "frame"], capture_output=True, encoding="utf8")
    for line in p.stdout.splitlines():
        stream, port, _ = line.split("\t", 2)
        SP_BF.add(port)
        RX_BF = RX_BF + 1
    SP_BF = len(SP_BF)
    p = subprocess.run(["tshark", "-n", "-r", PCAP, "-Y", f"ip.dst == {IP} and tcp.dstport == {PORT} and tcp.payload contains \"A\"", "-T", "fields", "-e", "tcp.stream", "-e", "tcp.srcport", "-e", "frame"], capture_output=True, encoding="utf8")
    for line in p.stdout.splitlines():
        stream, port, _ = line.split("\t", 2)
        SP_TOTAL.add(port)
        TX_TOTAL=TX_TOTAL + 1
    SP_TOTAL = len(SP_TOTAL)

    print(f"""
Report for {IP}/{HOSTNAME} at {WHEN}

PCAP in {PCAP}

OK packets: TX {TX_TOTAL}, RX {RX_TOTAL}
Bitflip packets: {RX_BF} total, {((RX_BF/(RX_TOTAL+RX_BF))*100):.3f} % of all packets

Total connections: {SP_TOTAL}
Bitflip connections: {SP_BF} total, {((SP_BF / SP_TOTAL) * 100):.3f} % of all connections
""")
