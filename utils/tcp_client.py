#!/usr/bin/env python3

import argparse
import socket
import sys
import time

LOCALHOST = "127.0.0.1"

parser = argparse.ArgumentParser("Simple TCP Client")
# parser.add_argument(
#     "--localip",
#     default=LOCALHOST,
#     help="The local IP address on which to bind the TCP client socket",
#     type=str,
# )
# parser.add_argument(
#     "--localport",
#     required=True,
#     help="The local port on which to bind the TCP client socket",
#     type=int,
# )
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

    # LOCALIP = argvars["localip"]
    # LOCALPORT = argvars["localport"]
    REMOTEIP = argvars["remoteip"]
    REMOTEPORT = argvars["remoteport"]

    awaiting_input = False
    connected = False
    received = False
    message_sent = False
    msg = ""

    # outer try/except to catch SIGINT, connection errors
    try:
        while True:
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # skipped on the first iteration
            while awaiting_input:
                print(
                    "To repeat previous values, press [enter] with no input. To exit, input `Q` or `q`"
                )
                remoteip_input = ""
                remoteip_input = input(
                    "Enter new remote IP address (previous: {}): ".format(REMOTEIP)
                )

                if remoteip_input.lower() == "q":
                    print("Closing client and exiting...")
                    clientsocket.close()
                    sys.exit()

                REMOTEIP = REMOTEIP if (len(remoteip_input) == 0) else remoteip_input

                remoteport_input = ""
                remoteport_input = input(
                    "Enter a new remote port (previous: {}): ".format(REMOTEPORT)
                )

                if remoteport_input.lower() == "q":
                    print("Closing client and exiting...")
                    clientsocket.close()
                    sys.exit()

                REMOTEPORT = (
                    REMOTEPORT if (len(remoteport_input) == 0) else remoteport_input
                )

                awaiting_input = False

            while not connected:
                # inner try/except to catch socket connection errors
                try:
                    print(
                        "TCP Client connecting to {}:{}...".format(REMOTEIP, REMOTEPORT)
                    )
                    clientsocket.connect((REMOTEIP, int(REMOTEPORT)))
                    connected = True

                    while not message_sent:
                        msg = input("Enter message to tunnel to remote...\n")

                        if msg.lower() == "q":
                            print("Closing client and exiting...")
                            if connected:
                                clientsocket.shutdown(socket.SHUT_RDWR)
                            clientsocket.close()
                            sys.exit()

                        if len(msg) > 0:
                            print("\nSending message...")
                            clientsocket.sendall(bytes(msg, encoding="utf8"))
                            msg = ""
                            message_sent = True

                        # explicitly conditional on this so connection failures will not enter this and loop around/restart
                        while not received:
                            print("Awaiting response...")
                            buf = clientsocket.recv(4096)

                            if len(buf) == 0:
                                print("EOF reached!")

                            if len(buf) > 0:
                                print("Response received:\n")
                                print(buf.decode())

                            received = True

                except ConnectionRefusedError:
                    print(
                        "TCP connection to {}:{} refused!".format(REMOTEIP, REMOTEPORT)
                    )

                    break

            if connected:
                clientsocket.shutdown(socket.SHUT_RDWR)

            clientsocket.close()
            print("\nClient connection closed\n")

            awaiting_input = True
            connected = False
            message_sent = False
            received = False

    except KeyboardInterrupt or ConnectionError or ConnectionResetError:
        print("Shutting down TCP client...")

        if connected:
            clientsocket.shutdown(socket.SHUT_RDWR)

        clientsocket.close()
        sys.exit()
