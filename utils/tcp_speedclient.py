#!/usr/bin/env python3

import argparse
import random
import socket
import sys
import os
import time

LOCALHOST = "127.0.0.1"

_kibibytes = 1024
_mibibytes = 1024 * _kibibytes
_gibibytes = 1024 * _mibibytes

DEFAULT_SENDSIZE = 40 * _mibibytes

parser = argparse.ArgumentParser("Simple TCP Cannon")
parser.add_argument(
    "--size",
    default=DEFAULT_SENDSIZE,
    help="The number of bytes to send",
    type=int,
)
parser.add_argument(
    "--remoteip",
    default=LOCALHOST,
    help="The remote IP address to which the TCP client should connect to",
    type=str,
)
parser.add_argument(
    "--remoteport",
    required=True,
    help="The remote port to which the TCP client should connect to",
    type=int,
)

if __name__ == "__main__":
    argvars = vars(parser.parse_args())

    SENDSIZE = argvars["size"]
    REMOTEIP = argvars["remoteip"]
    REMOTEPORT = argvars["remoteport"]

    connected = False

    # outer try/except to catch SIGINT, connection errors
    try:
        if SENDSIZE <= 0:
            raise RuntimeError("SENDSIZE must be greater than 0!")

        clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("Pregenerating msg of size {}B...".format(SENDSIZE))

        msg = bytearray(os.urandom(SENDSIZE))

        print("\nTCP Client connecting to {}:{}...".format(REMOTEIP, REMOTEPORT))

        t1 = time.time()

        clientsocket.connect((REMOTEIP, int(REMOTEPORT)))

        t2 = time.time()
        connected = True

        print("Sending payload...")
        clientsocket.sendall(msg)

        clientsocket.shutdown(socket.SHUT_WR)
        t3 = time.time()

        print("Payload away...")

        buf = clientsocket.recv(4096)
        t4 = time.time()

        ping = ((t2 - t1) + (t4 - t3)) / 2
        sendtime = t3 - t2
        bandwidth = (SENDSIZE / sendtime) * 2e-6

        print("\nPayload Transmitted:")
        print("Ping: {}".format(ping))
        print("Time: {}".format(sendtime))
        print("Bandwidth (MB/s): {}\n".format(bandwidth))

        result = "Response: "

        if len(buf) > 0:
            val = int(buf.decode())
            percent = val / SENDSIZE * 100
            result += "{}/{} Bytes ({}%) received by remote!".format(
                val, SENDSIZE, percent
            )
        else:
            result += "< NONE RECEIVED >"

        print(result)

    except KeyboardInterrupt or ConnectionError or ConnectionResetError or RuntimeError:
        print("Shutting down TCP client...")

        if connected:
            clientsocket.shutdown(socket.SHUT_RDWR)

        clientsocket.close()
        sys.exit()
