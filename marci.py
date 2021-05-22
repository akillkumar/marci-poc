import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
#from cryptography.hazmat.primitives.asymmetric.ed25519 import \
#        Ed25519PublicKey, Ed25519PrivateKey

from Crypto.Cipher import AES

from helper import *

'''
    Symmetric Ratchet
'''
class SRatchet (object):
    def __init__ (self, key):
        self.state = key
    
    # one turn of the ratchet
    def next (self, inp = b''):
        # change the state
        # get new key + IV
        output = hkdf (self.state + inp, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]

        return outkey, iv


'''
    Client class
'''
class Client:

    def __init__ (self):
        # generate pre-key bundle
        # ideally, this is published to a server
        self.IK = X25519PrivateKey.generate ()   # identity key
        self.SPK = X25519PrivateKey.generate ()  # signed pre-key
        self.OPK = X25519PrivateKey.generate () # one time key

        # initiator - boolean to determine whether this client is initating a connection
        # helps with x3dh, i think ... 
        self.init = False

    '''
        when initiating a connection with another client
    '''
    def init_connect (self, client):
        # generate an ephimeral key to connect with bob
        self.EK = X25519PrivateKey.generate ()
        
        # perform X3DH
        dh1 = self.IK.exchange (client.SPK.public_key ())
        dh2 = self.EK.exchange (client.IK.public_key ())
        dh3 = self.EK.exchange (client.SPK.public_key ())
        dh4 = self.EK.exchange (client.OPK.public_key ())

        # shared key = KDF (dh1 | dh2 | dh3 | dh4)
        self.sk = hkdf (dh1 + dh2 + dh3 + dh4, 32)

        # set initiator to True
        self.init = True

        print (COLORS.cyan + "[Alice]\tShared Key:" + b64(self.sk) + COLORS.clear)

    '''
        when connecting to another client
    '''
    def connect (self, client):
        # perform X3DH
        dh1 = self.SPK.exchange (client.IK.public_key())
        dh2 = self.IK.exchange  (client.EK.public_key())
        dh3 = self.SPK.exchange (client.EK.public_key())
        dh4 = self.OPK.exchange (client.EK.public_key())

        # shared key = KDF (dh1 | dh2 | dh3 | dh4)
        self.sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)

        # after using the OPK, make a new one 
        self.OPK = X25519PrivateKey.generate () 

        print (COLORS.cyan + "[Bob]\tShared Key:" + b64(self.sk) + COLORS.clear)

    '''
        initialize both symmetric and DH ratchets
    '''
    def init_ratchets (self):
        # init root chain with shared key
        self.root_ratchet = SRatchet (self.sk) 

        '''
            Alice's sending ratchet should match with Bob's receiving ratchet
                and vice versa
        '''
        if self.init:
            # initialize send and receive chains for the initiator
            self.send_ratchet = SRatchet (self.root_ratchet.next ()[0])
            self.recv_ratchet = SRatchet (self.root_ratchet.next ()[0])

            # also initialize the DH ratchet
            self.DHratchet = None
        else:
            # initialize send and receive chains for the initiated party
            self.recv_ratchet = SRatchet (self.root_ratchet.next ()[0])
            self.send_ratchet = SRatchet (self.root_ratchet.next ()[0])

            # initialize the DH ratchet for initiated party
            self.DHratchet = X25519PrivateKey.generate ()

    '''
        perform a DH ratcher rotation
    '''
    def dh_next (self, client_public):
        # perform a DH ratchet rotation 
        if self.DHratchet is not None:
            # the first time, alice (initiator) does not have a DH ratchet 
            dh_recv = self.DHratchet.exchange (client_public)
            shared_recv = self.root_ratchet.next (dh_recv)[0]

            # use client's pubkey and our old key
            self.recv_ratchet = SRatchet (shared_recv)

        # generate a new key pair and send ratchet
        # our new public key will be sent with the next message to Bob
        self.DHratchet = X25519PrivateKey.generate()
        dh_send = self.DHratchet.exchange(client_public)
        
        shared_send = self.root_ratchet.next(dh_send)[0]
        self.send_ratchet = SRatchet(shared_send)
        

    '''
        send a message to another client
    '''
    def send (self, client, msg):
        # turn send ratchet and get new key and IV
        key, iv = self.send_ratchet.next ()

        # encrypt message using AES 
        ciphertext = AES.new (key, AES.MODE_CBC, iv).encrypt(pad(msg))

        print (("[Alice]" if self.init else "[Bob]") + "\tSend: ", b64(ciphertext), COLORS.clear)

        client.recv (ciphertext, self.DHratchet.public_key ())

    
    '''
        receive a message from a client
    '''
    def recv (self, ciphertext, pub_key):
        # receive client's new public key
        self.dh_next (pub_key)

        # turn recv ratchet and get new key and IV
        key, iv = self.recv_ratchet.next ()

        # decrypt ciphertext
        msg = unpad (AES.new (key, AES.MODE_CBC, iv).decrypt(ciphertext))

        print (COLORS.green + ("[Alice]" if self.init else "[Bob]") + "\tReceived:", msg, COLORS.clear)



alice = Client ()
bob = Client ()

alice.init_connect (bob)
bob.connect (alice)

# Initialize their symmetric ratchets
alice.init_ratchets()
bob.init_ratchets()

print ("")

# Initialise Alice's sending ratchet with Bob's public key
alice.dh_next (bob.DHratchet.public_key())

# Alice sends Bob a message and her new DH ratchet public key
alice.send(bob, b'Hello Bob!')

# Bob uses that information to sync with Alice and send her a message
bob.send(alice, b'Hello to you too, Alice!')

