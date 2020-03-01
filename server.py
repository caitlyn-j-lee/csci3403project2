"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Anna Nuggehalli, Caitlyn Lee, and Rachel Rockenfeller 



"""

import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP as pkcs1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


host = "localhost"
port = 10001

# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)

def helper():
	#password must have a b in front
	kf = open("keys", "rb")
	private_Key = serialization.load_pem_private_key(kf.read(),password=b'apple',backend=default_backend())
	kf.close()
	print("fooey")
	return private_Key

# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    #Reference:https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
    
    #session_key = the encrypted session key from the client side of things. We must decrypt that using the server's private
    #key and return the AES key
    private_Key = helper()
    decrypt_AES_key = private_Key.decrypt(session_key,padding=padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None,))
    print("kitty",decrypt_AES_key)
    return decrypt_AES_key
    


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    #techtutorialsx.com ref
    cipher = AES.new(session_key, AES.MODE_ECB)
    decMessage = cipher.decrypt(client_message)
    print("decMessage")
    print('decrypt message done')
    return decMessage


# Encrypt a message using the session key
def encrypt_message(message, session_key):
	# TODO: Implement this function
	#techtutorialsx.com ref
	length_Message = len(message)
	
	#integer division to get proper padding
	padding = ((length_Message + 16) // 16) * 16 
	padded_Message = message + " "*(padding-length_Message)
	cipher = AES.new(session_key, AES.MODE_ECB)
	encMessage = cipher.encrypt(padded_Message)
	print('encrypt message done')
	return encMessage


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                # hashed_password =
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)
                print("decrypted AES", plaintext_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)
                print("plooey", ciphertext_message)
				
                # TODO: Decrypt message from client
                plaintext_ciphertext = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password
                print(plaintext_ciphertext)
                #message = verify_hash(user, password)
                message = "True"

                # TODO: Encrypt response to client
                ciphertext_response = encrypt_message(message, plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
