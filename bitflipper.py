#!/usr/bin/env python3

import argparse
import asyncio
import atexit
import binascii
import json
import logging
import socket
import statistics
import struct
import subprocess
import tempfile
import time


logger = logging.getLogger(__name__)

processes = []


def cleanup():
    for p in processes:
        p.kill()


atexit.register(cleanup)


class QualityCommon:
    def __init__(self, args):
        self.args = args
        self.time_start = time.time()
        self.results = {}
        self.packets = {}
        self.token = self.args.token.encode()

    def generate_data(self, index, length):
        last = struct.pack("L", index)
        result = b""
        while len(result) < length:
            last = binascii.crc32(last)
            last = struct.pack("L", last)
            result = result + last
        return result[:length]

    def receive(self, packet):
        data = bytes(packet[UDP].payload)
        if data[: len(self.token)] != self.token:
            return
        index, timestamp = struct.unpack(
            "Qd", data[len(self.token) : len(self.token) + 16]
        )
        if index not in self.results:
            self.results[index] = set()
        self.results[index].add((float(packet.time - timestamp), data))

    async def run(self):
        iface = conf.route.route(self.args.ip)[0]
        filter = f"udp and src host {self.args.ip} and src port {int(self.args.port)}"
        pcap_file = tempfile.NamedTemporaryFile()
        process_pcap = subprocess.Popen(
            ["tcpdump", "-i", iface, "-s", "0", "-w", pcap_file.name, "-U", filter]
        )
        processes.append(process_pcap)

        index = 0
        await asyncio.sleep(1)
        for c in range(0, self.args.connections, self.args.parallel):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 40000 + (c % 20000)))
            sock.connect((self.args.ip, self.args.port))
            for n in range(self.args.num_packets):
                for p in range(min(self.args.parallel, self.args.connections - c)):
                    index = index + 1
                    packet = self.generate_packet(c, index)
                    sock.send(packet)
                    if index % 1000 == 0:
                        logging.info(
                            f"Sent {index} packets out of {self.args.num_packets * self.args.connections}"
                        )
                    if index / (time.time() - self.time_start) < self.args.rate * 1000:
                        await asyncio.sleep(1 / self.args.rate)
            sock.close()
        await asyncio.sleep(1)

        process_pcap.terminate()
        await asyncio.sleep(2)
        if process_pcap.poll() is None:
            process_pcap.kill()
        processes.remove(process_pcap)
        for packet in rdpcap(pcap_file.name):
            self.receive(packet)
        pcap_file.close()

        packet_loss = 0
        packet_dup = 0
        packet_latency = 0
        packet_count = 0
        packet_corrupt = 0
        packet_seen = set()
        rtt = []
        for index, packets in self.results.items():
            for packet in packets:
                (latency, data) = packet
                if index in packet_seen:
                    packet_dup = packet_dup + 1
                else:
                    packet_seen.add(index)
                rtt.append(latency * 1000)
                packet_latency = packet_latency + latency
                if data != self.packets[index]:
                    packet_corrupt = packet_corrupt + 1
                packet_count = packet_count + 1
        for index in self.packets:
            if index not in packet_seen:
                packet_loss = packet_loss + 1

        if packet_count:
            rtt_min = min(rtt)
            rtt_max = max(rtt)
            rtt_mean = statistics.mean(rtt)
            rtt_stdev = statistics.stdev(rtt)
        else:
            rtt_min = float("NaN")
            rtt_max = float("NaN")
            rtt_mean = float("NaN")
            rtt_stdev = float("NaN")
        if self.args.json:
            result = {
                "sent": len(self.packets),
                "received": packet_count,
                "lost": packet_loss,
                "dup": packet_dup,
                "corrupt": packet_corrupt,
                "rtt_min": rtt_min,
                "rtt_mean": rtt_mean,
                "rtt_max": rtt_max,
                "rtt_stdev": rtt_stdev,
            }
            print(json.dumps(result))
        else:
            print(
                f"""Statistics:

Packets Sent:     {len(self.packets)}
Packets Received: {packet_count}
Packets Lost:     {packet_loss}
Packets Dup:      {packet_dup}
Packets Corrupt:  {packet_corrupt}
Packets RTT:      min:   {rtt_min:.03}ms
                  mean:  {rtt_mean:.04}ms
                  max:   {rtt_max:.04}ms
                  stdev: {rtt_stdev:.04}ms
"""
            )


class QualityClient(QualityCommon):
    def generate_packet(self, connection, index):
        data = self.token + struct.pack("Qd", index, time.time())
        data = data + self.generate_data(index, self.args.length - len(data))
        self.packets[index] = data
        return data


class QualityServerProtocol:
    def __init__(self, token):
        self.token = token
        super().__init__()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if data[: len(self.token)] == self.token:
            self.transport.sendto(data, addr)


class QualityServer(QualityCommon):
    async def run(self):
        print("Starting UDP server", self.args.port)

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: QualityServerProtocol(self.token),
            local_addr=(self.args.ip, self.args.port),
        )

        try:
            while True:
                await asyncio.sleep(3600)  # Server forever
        finally:
            transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="bitflipper",
        description="Check connection for bitflips and other problems in packets",
    )

    parser.add_argument(
        "-C",
        "--connections",
        default=400,
        type=int,
        help="Total number of connections to use, with unique source ports (1-10000, default: 400)",
    )
    parser.add_argument(
        "-P",
        "--parallel",
        default=10,
        type=int,
        help="Number of parallel connections to use, this does not affect the total number of connections to use (1-25, default: 10)",
    )
    parser.add_argument(
        "-N",
        "--num-packets",
        default=150,
        type=int,
        help=" Number of data packets to send per connection (1-1000, default: 10)",
    )
    parser.add_argument(
        "-L",
        "--length",
        default=1400,
        type=int,
        help=" Number of bytes to put in each data packet (1-10000, default: 1400)",
    )
    parser.add_argument(
        "-R",
        "--rate",
        default=100,
        type=float,
        help="Limit how many data packets to send per second (1-1000, default: 100)",
    )
    parser.add_argument(
        "-p",
        "--port",
        default=65112,
        type=int,
        help="Port to connect to (0-65535, default: 65112)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable debugging",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-j",
        "--json",
        help="Output in json",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-s",
        "--server",
        help="Run in server mode",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-c",
        "--client",
        help="Run in client mode",
        default=False,
    )
    # parser.add_argument('-4', '--ipv4', help="Force to use ipv4", action='store_true', required=False, default=False)
    # parser.add_argument('-6', '--ipv6', help="Force to use ipv6", action='store_true', required=False, default=False)
    # parser.add_argument('-t', '--tcp', help="Use TCP instead of UDP", action='store_true', required=False, default=False)
    parser.add_argument("ip", help="IP to connect to (client) or bind to (server) ")
    parser.add_argument("token", help="Token to authenticate with")

    args = parser.parse_args()
    C = args.connections
    P = args.parallel
    N = args.num_packets
    L = args.length
    R = args.rate
    PORT = args.port
    VERBOSE = args.verbose
    IP = args.ip

    assert (
        args.connections >= 1 and args.connections <= 10000
    ), "Connections must be between 1 and 10000"
    assert (
        args.parallel >= 1 and args.parallel <= 25
    ), "Parallel connections must be between 1 and 25"
    assert (
        args.num_packets >= 1 and args.num_packets <= 1000
    ), "Number of data packets per connection must be between 1 and 1000"
    assert (
        args.length >= 1 and args.length <= 10000
    ), "Number of bytes in each data packet must be between 1 and 10000"
    assert (
        args.rate >= 1 and args.rate <= 1000
    ), "Number of data packets per second must be between 1 and 1000"
    assert args.port >= 0 and args.port <= 65535, "Port must be between 0 and 65535"

    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(level=level)

    if args.server:
        runner = QualityServer(args)
    else:
        from scapy.all import UDP, conf, rdpcap # we only need this import for the client
        runner = QualityClient(args)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(runner.run())
