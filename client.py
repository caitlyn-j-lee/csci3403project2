"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Anna Nuggehalli, Caitlyn Lee, and Rachel Rockenfeller 



"""

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP as pkcs1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


host = "localhost"
port = 10001

#Reference: https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
pubkey = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsgTyA8bu6ee/31pG8C3YKiR6BiXhos1leC0DN8jbriWeipM4rGKdaSQBKGdX3U82MeaHL3Gzld5skFQamwzqVNyZkMQzQ36g6CWOKTW2jVGypniksxoBc8dvhu4BnI9hN3TuKPDV7hvaXpWCsqJWACIB6Hxe9YTUHJRqKVvABU7o4fp7c8lqZGk1Edzvt3quNAVfd0OSy3yc2dn8aBPaH1FCl71NGD7vbSUi1rO4p5j7W97jo+vGi4YWX7h2kC7YV+sN9lFLL534q/2gK4w4RlVmbOxtM4nkEuC+XgeyrkRsMUl897qe6OzELoP5ItIncixLQbiSe4cemSgLaRl1J rachel3729@rachel3729-VirtualBox"""

# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    return os.urandom(16)
    

# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    
    #message = session_key. We must encrypt this session key with the server's public key so no one can know the AES session key
    kf = open("keys.pem", "rb")
    public_key = serialization.load_pem_public_key(kf.read(),backend=default_backend())
    kf.close()
    cipher_message = public_key.encrypt(session_key,padding=padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),algorithm=hashes.SHA1(),label=None,))
    return cipher_message


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    #techtutorialsx.com/2018/04/09python-pycrypto-using-aes-128-in-ecb-mode/
	length_Message = len(message)
	
	#integer division to get proper padding
	padding = ((length_Message + 15) // 16) * 16 
	padded_Message = message + " "*(padding-length_Message)
	cipher = AES.new(session_key, AES.MODE_ECB)
	encMessage = cipher.encrypt(padded_Message)
	return encMessage
    

# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    #techtutorialsx.com/2018/04/09python-pycrypto-using-aes-128-in-ecb-mode/
    cipher = AES.new(session_key, AES.MODE_ECB)
    decMessage = cipher.decrypt(message)
    decMessage = decMessage.strip()
    return decMessage
    
     
# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)
        

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        encrypted_Message = encrypt_message(message, key)
        send_message(sock, encrypted_Message)

        # TODO: Receive and decrypt response from server
        message = receive_message(sock)
        final_Message = decrypt_message(message, key)
        
        result = final_Message.decode()        
        
        if result == "True": print("User successfully authenticated!")
        else: print("Password or username incorrect")
        
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
