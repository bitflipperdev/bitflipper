This tool allows you to test packet-loss, jitter, duplicates and bit-flips.

The tool is based on the bitflipping research as presented at
[NLNOG 2024 - Frank van Vliet - Debugging the impossible the bit flipping story](https://www.youtube.com/watch?v=G_Ir_gRlst0). 

The idea of this tool is as follows:

1. Send packets from a client to a server and back
2. Ensure the same data is returned (no bit flips) and record the time
3. Use multiple connections to trigger multiple paths in ECMP and friends
4. Detect packetloss, jitter, duplicates and bit-flips

Notes:
- To prevent reflection attacks, each packet contains a token for authentication.
- Currently, the tool uses UDP
- Currently, the tool requires access to run tcpdump

Main loop:
- For C connections 
  - Send N packets per connection
  - Check returned packets to have same data and record timestamps

```
usage: bitflipper [-h] [-C CONNECTIONS] [-P PARALLEL] [-N NUM_PACKETS] [-L LENGTH] [-R RATE] [-p PORT] [-v] [-j] [-s] [-c CLIENT] ip token

Check connection for bitflips and other problems in packets

positional arguments:
  ip                    IP to connect to (client) or bind to (server)
  token                 Token to authenticate with

options:
  -h, --help            show this help message and exit
  -C CONNECTIONS, --connections CONNECTIONS
                        Total number of connections to use, with unique source ports (1-10000, default: 400)
  -P PARALLEL, --parallel PARALLEL
                        Number of parallel connections to use, this does not affect the total number of connections to use (1-25, default:
                        10)
  -N NUM_PACKETS, --num-packets NUM_PACKETS
                        Number of data packets to send per connection (1-1000, default: 10)
  -L LENGTH, --length LENGTH
                        Number of bytes to put in each data packet (1-10000, default: 1400)
  -R RATE, --rate RATE  Limit how many data packets to send per second (1-1000, default: 100)
  -p PORT, --port PORT  Port to connect to (0-65535, default: 65112)
  -v, --verbose         Enable debugging
  -j, --json            Output in json
  -s, --server          Run in server mode
  -c CLIENT, --client CLIENT
                        Run in client mode
```


## Basic usage

Get a random token:
```
openssl rand -hex 12
```

Run the server:
```
bitflipper.py -s 0.0.0.0 <token>
```

Run the client:
```
bitflipper.py ip-of-server <token>
```


Example output:
```
tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
INFO:root:Sent 1000 packets out of 60000
INFO:root:Sent 2000 packets out of 60000
INFO:root:Sent 3000 packets out of 60000
INFO:root:Sent 4000 packets out of 60000
INFO:root:Sent 5000 packets out of 60000
...
INFO:root:Sent 55000 packets out of 60000
INFO:root:Sent 56000 packets out of 60000
INFO:root:Sent 57000 packets out of 60000
INFO:root:Sent 58000 packets out of 60000
INFO:root:Sent 59000 packets out of 60000
INFO:root:Sent 60000 packets out of 60000
59999 packets captured
59999 packets received by filter
0 packets dropped by kernel
Statistics:

Packets Sent:     60000
Packets Received: 59999
Packets Lost:     1
Packets Dup:      0
Packets Corrupt:  0
Packets RTT:      min:   3.67ms
                  mean:  4.586ms
                  max:   129.9ms
                  stdev: 1.078ms
```
