import struct
import calendar
import time

from Crypto.Cipher import XOR
import Crypto.Random as Random
from Crypto.Cipher import AES as AES
from Crypto.Protocol import KDF
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
	def __init__(self, conn, client=False, server=False, verbose=False):
		self.conn = conn
		self.hashMAC = None
		self.cipher = None
		self.iv = None
		self.salt = None
		self.shared_hash = None
		self.client = client
		self.server = server
		self.verbose = verbose
		self.initiate_session()

	def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
		### TODO: Your code here!
		# This can be broken into code run just on the server or just on the client
		if self.server or self.client:
			my_public_key, my_private_key = create_dh_key()
			# Send them our public key
			self.send(bytes(str(my_public_key), "ascii"))
			# Receive their public key
			their_public_key = int(self.recv())
			# Obtain our shared secret
			self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
			print("Shared hash: {}".format(self.shared_hash))
			self.salt = Random.new().read(64)	#randomly generate a 64 bit salt
			print("64 bit salt: " + str(self.salt) + "\n")
			derivedKey = KDF.PBKDF2(self.shared_hash,self.salt,32)	#generate derived key from salt, length should be 32 bits so that when split in 2, it provides a 16 bit key for AES
			print("32 bit derived key: " + str(derivedKey) + "\n");
			cipherKey, HMACkey = derivedKey[:16], derivedKey[16:]	#split derived key in half and use each 16 bit half as cipher and hmac key respectively
			print("16 bit cipher and hmac keys" + str(cipherKey) + ", " + str(HMACkey) + "\n")
			self.iv = Random.new().read(AES.block_size)	#randomly generate initialisation vector the size of the AES block size
			self.cipher = AES.new(cipherKey, AES.MODE_CBC, self.iv)	#generate cipher object with cipher key
			self.hashMAC = HMAC.new(HMACkey, digestmod = SHA512)	#generate HMAC object with HMAC key

	def send(self, data):
		if self.cipher:
			timestamp = str(calendar.timegm(time.gmtime()))	#get the current epoch in seconds then convert to a string 
			data = bytes(timestamp, 'ascii') + data 	#append epoch in bytes to end of data to prevent replay attacks
			padding = 16 - len(data)%16
			data += bytes([padding])*padding
			ciphertext = self.cipher.encrypt(data)
			self.hashMAC.update(self.salt + self.iv + ciphertext)
			encrypted_data = self.salt + self.iv + ciphertext + bytes(self.hashMAC.hexdigest(),'ascii')	#send salt, IV, ciphertext and HMAC
			print ("Final message, self.salt + self.iv + ciphertext + bytes = " + str(encrypted_data))
			if self.verbose:
				print("Original data: {}".format(data))
				print("Encrypted data: {}".format(repr(encrypted_data)))
				print("Sending packet of length {}".format(len(encrypted_data)))
		else:
			encrypted_data = data
		# Encode the data's length into an unsigned two byte int ('H')
		pkt_len = struct.pack('H', len(encrypted_data))
		self.conn.sendall(pkt_len)
		self.conn.sendall(encrypted_data)
	def recv(self):
		print("got to here\n")
		# Decode the data's length from an unsigned two byte int ('H')
		pkt_len_packed = self.conn.recv(struct.calcsize('H'))
		unpacked_contents = struct.unpack('H', pkt_len_packed)
		pkt_len = unpacked_contents[0]
		encrypted_data = self.conn.recv(pkt_len)

		if self.cipher:	
			salt = encrypted_data[0:64]	#extract salt from received msg
			print("salt: " + str(salt) + "\n")
			iv = encrypted_data[64:80]	#extract IV from received msg
			print("iv: " + str(iv) + "\n")
			msg_hash = encrypted_data[-128:].decode('ascii')	#extract hash from msg
			msg = encrypted_data[80:-128]			#extract ciphertext from msg
			derivedKey = KDF.PBKDF2(self.shared_hash,salt,32)	#generate derived key from salt, length should be 32 bits so that when split in 2, it provides a 16 bit key for AES
			cipherKey, HMACkey = derivedKey[:16], derivedKey[16:]	#split derived key in half and use each 16 bit half as cipher and hmac key respectively
			cipherfn = AES.new(cipherKey, AES.MODE_CBC, iv)	#generate cipher object with cipher key
			HMACfn = HMAC.new(HMACkey, digestmod = SHA512)	#generate HMAC object with HMAC key
			data = cipherfn.decrypt(encrypted_data)
			#timestamp = int((data[0:10]).decode('ascii'))
			actualtime = calendar.timegm(time.gmtime())
			hash_tmp = HMACfn.update(salt + iv + cipherfn.encrypt(data))	#Check hash of received data
			hash_check = HMACfn.hexdigest()
			if str(hash_check) == str(msg_hash):	#check if calculated hash matches that of the hash sent
				print("Message has been hash verified. It has been authenticated.")	#if they match, tell the user they are likely safe
			else:
				print(str(hash_check))
				print(str(msg_hash))
				print("The hash of this message does not match it's content. It is suspicious and data is likely to be corrupt.")	#if they do not match, alert the user
			#if abs(actualtime - timestamp) > 60:	#check if the timestamp of the message differs from now by more than a minute
				#print("Message timestamp exceeded the time threshold. Message may be subject of a replay attack!")	#alert the user if the above condition is true
			if self.verbose:
				print("Receiving packet of length {}".format(pkt_len))
				print("Encrypted data: {}".format(repr(encrypted_data)))
				print("Original data: {}".format(data))
		else:
			data = encrypted_data

		return data

	def close(self):
		self.conn.close()
