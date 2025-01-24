This tool allows you to test packet-loss, jitter, duplicates and bitflips.

The tool is based on the bitflipping research as presented at
[NLNOG 2024 - Frank van Vliet - Debugging the impossible the bit flipping story](https://www.youtube.com/watch?v=G_Ir_gRlst0). 

The idea of this tool is as follows:

1. Send packets from a client to a server and back
2. Ensure the same data is returned (no bit flips) and record the time
3. Use multiple connections to trigger multiple paths in ECMP and friends

Notes:
- To prevent reflection attacks, each packet contains a token for authentication.
- Currently, the tool uses UDP
- Currently, the tool requires access to run tcpdump

Main loop:
- For C connections 
  - Send N packets per connection
  - Check returned packets to have same data and record timestamps

Main things to tweak:
- Number of connections (C)
- Number of packets to send per connecion (N)
- Length of the data of each packet (L)
- How many of these connections to have in parallel (P)
- How many packets to send as maximum per second (R) for everything combined

Basic usage:

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

