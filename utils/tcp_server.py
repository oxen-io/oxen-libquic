#!/usr/bin/env python3

import argparse
import socket
import sys

READSIZE = 4096

parser = argparse.ArgumentParser("Simple TCP Server")
parser.add_argument(
    "--localip",
    default="127.0.0.1",
    help="The local IP address on which to bind the TCP client socket",
    type=str,
)
parser.add_argument(
    "--localport",
    required=True,
    help="The local port on which to bind the TCP client socket",
    type=int,
)

if __name__ == "__main__":
    argvars = vars(parser.parse_args())

    LOCALIP = argvars["localip"]
    LOCALPORT = argvars["localport"]

    print("Starting TCP server...")

    serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversock.bind((LOCALIP, LOCALPORT))
    serversock.listen(1)

    print("TCP server listening at {}:{}...".format(LOCALIP, LOCALPORT))

    while True:
        try:
            conn, addr = serversock.accept()
            remote = "{}:{}".format(addr[0], addr[1])

            print("\nAccepted connection from {}".format(remote))

            buf = b""

            while True:
                b = conn.recv(READSIZE)
                buf += b
                if not b:
                    break

            size = len(buf)
            print("Received {}B from {}".format(size, remote))

            conn.sendall(bytes("{}".format(size), encoding="utf8"))

            # conn.shutdown(socket.SHUT_RDWR)
            conn.close()

            print("Connection to {} closed!".format(remote))

        except socket.error or ConnectionError or ConnectionResetError or RuntimeError:
            print("Remote {} disconnected! Continuing...".format(remote))
            conn.close()
            pass

        except KeyboardInterrupt:
            print("Shutting down TCP server...")
            serversock.shutdown(socket.SHUT_RDWR)
            serversock.close()
            sys.exit()
