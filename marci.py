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

########################################################
#                  HELPER FUNCTIONS                    #
########################################################

def b64 (msg):
    # too much of a pain to write this every time
    return base64.encodebytes(msg).decode('utf-8').strip()

########################################################
#                     DRIVER CODE                      #
########################################################

with socket.socket (socket.AF_INET, socket.SOCK_STREAM) as client:

     # connect to the server
    try:
        client.connect (server_addr)
        print (COLORS.green + "Connected to server" + COLORS.clear)
    except:
        print (COLORS.red + "Could not establish connection to server" + COLORS.clear)
        os._exit(1)

    

    