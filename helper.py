'''
    helper.py
    Custom helper file for marci
'''

import random
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

encoding = 'utf-8'

class COLORS:
	clear = '\033[0m'
	blue  = '\033[94m'
	green = '\033[92m'
	cyan  = '\033[96m'
	red   = '\033[91m'
	yell  = '\033[93m'
	mag   = '\033[35m'

server_addr = ('127.0.0.1', 9000)

SIG_CREATE = "1"
SIG_AUTH   = "2"

NUM_TRIALS = 10
NUM_KEYS = 5

# first 200 prime numbers! 
Primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 
   67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
   157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 
   251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,317, 331, 337, 347, 349, 
   353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 
   457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 
   571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 
   673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 
   797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 
   911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 
   1021,1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 
   1009, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223]

keysize = 100

def gcd (a, b):
	while a != 0:
		a, b = b % a, a
	return b

'''
Find multiplicative modular inverse 
'''
def modInverse(a, m):
	# Make sure that they are relatively prime 
   if gcd(a, m) != 1:
      return None

   u1, u2, u3 = 1, 0, a
   v1, v2, v3 = 0, 1, m
   
   while v3 != 0:
      q = u3 // v3
      v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
   return u1 % m

'''
Primality Testing with the Rabin-Miller Algorithm
http://inventwithpython.com/hacking (BSD Licensed) - Modified by Akhil Kumar
'''
def miller_rabin(num):
	# Returns True if num is a prime number.
	s = n = num - 1
	t = 0

	while s % 2 == 0:
		# keep halving s while it is even (and use t
		# to count how many times we halve s)
		s //= 2
		t += 1

	for trials in range(3):
		a = random.randrange(2, n)
		v = pow(a, s, num)
		
		if v != 1: # this test does not apply if v is 1.
			i = 0
			while v != n:
				if i == t - 1:
					return False
				else:
					i = i + 1
					v = (v ** 2) % num
	return True

'''
Small checking before using Miller-Rabin
'''
def isPrime(num):
	# We will NEVER use such small number, can ignore this check
	if num in Primes:
		return True

	# About 1/3 of the time we can quickly determine if num is not prime
	# by dividing by the first few dozen prime numbers. This is quicker
	# than miller_rabin(), but unlike miller_rabin() is not guaranteed to
	# prove that a number is prime.
	# See if any of the low prime numbers can divide num
	for prime in Primes:
		if (num % prime == 0):
			return False

	# If all else fails, call miller_rabin() to determine if num is a prime.
	return miller_rabin(num)

'''
Generate a large prime number
'''
def gen(size = keysize/2):
	# Return a random prime number of size bits.
	while True:
		num = random.randrange(2**(size-1), 2**(size))
		if isPrime(num):
			return (num)


'''
 Modular exponentiation
'''
def modexp (m, e, n):
	res = 1  
	while (e > 0) : 
		# If exponent is odd
		if ((e & 1) == 1) : 
			res = (res * m) % n 

		# Our exponent must be even now 
		e = e >> 1
		m = (m * m) % n 

	return res


'''
 Generate random co-prime with a number N
'''
def get_coprime(N):
	while True:
		x = random.randrange (N)
		if gcd (x, N) == 1:
			return x



def b64 (msg):
    # too much of a pain to write this every time
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf (input, length):
    hkdf  = HKDF (algorithm = hashes.SHA256(), length = length, salt = b'', info = b'', backend = default_backend())
    return hkdf.derive (input)

def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]