import os
import socket
import random
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from Crypto.Cipher import AES

from helper import *


# create a socket
with socket.socket (socket.AF_INET, socket.SOCK_STREAM) as server:
    # bind to an (IP, port)
    server.bind (server_addr)

    # listen on this port
    server.listen (1)

    print (COLORS.blue + "Server running. Listening on", server_addr[0] + ":" + str(server_addr[1]) + COLORS.clear)

    while True:
        # accept client connection

        connection, client_addr = server.accept ()

        if connection:
            print (COLORS.green + "Connected to client", client_addr, COLORS.clear)

        


