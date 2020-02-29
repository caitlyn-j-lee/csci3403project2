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
from Crypto.Cipher import PKCS1_OAEP as pkcs1
from base64 import b64decode,b64encode

host = "localhost"
port = 10001



#Reference:https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
prvkey = """-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2562CAD057F6851839C9009BBB2FB171

JLRcwaRxQczqY9kaCv37iH+46buyrGxRVnAQnYNKO7tK8bzOHaTrGiH9PdbS2elB
VtNPpG2Z4W3wIAIqoVjoR0r9LUXD3jd36Vw8SvPAvqTgbICZeGNclEUBHR/Jn6yZ
m+7o9BgoBc69aqt4/OnprJZsJIK+rCQZrYqT8QYCSMc+JVc8bunmyAI0KH8sHQWX
A4W4TEkZdxm8lZ8jo/OXRbjLYr4Vki0XBp/D9HsbWJrQmfigTpWEL3tGpG2og2MO
5/CU4WpX/E3ZUUzO8M4RfaFbGVjfS3Or3StcF8/DMDr8HKisq/BUYZqgSwGLSNoV
Kveurn6sek1cbZEQ46+NntbV4CFhsfDCA3VAJrPpxY/xiiLNK/r4AHvXFZ+FZ50d
t3e3C/E6gdUYDdnvPbLkzVD7tHIyur+zphz7jFGc2bUiD7qy+3PDU6dPC4vvPowy
lWkz/5mrPYv3jiLNOvFGHR/jYi3iv/H0exN56d5RpefENsNQml484O7+ir8rTgHN
AZgiooxf/+Ue7NghHEea5bqKAmIaICLiHBxvr/wLfpNRPDRgt2cmYzr1nwqu0a5g
7uZBn1DK1ScIj40loAtfF8kd5lqglbeeRfqGVHWMKaEI1OCFBUUGFZY6IY1Bhd+O
HNuxgSopeUnDD2/jI/HUBzVyfx/2YE6wmYu+EmYfkCh6388mModuiin5/e/uY27N
wffEJLp9j/cox+b0hNRMoOa68BryCPze/vworqFoSApfCpASJRXcPKkeO4LEedee
mSMwGiynpMftszK91A4WrwqZ0+GJ7fab19gj5T7Q7GbXLBNcRNnBDayqKUlgJCS1
r6FF4BcgLaLCHKvIbaXcDgxovMCbxEFVEHn3YZNO80FPakFOx7ylCVPXQoK62Vgn
Nebn8AEtRjc/9E40z/qpM/CWeoi71pXtY5ti5i2hAnAFnz3lvNKV4CNklRS+HeV/
N3Mue47gTFbwKuyeUKNuUMky/v9JkT7tgO+Q4GSbbBJIZu+PSHC7qd4PxTtG8F6M
WbhpPAeTNXECVYmefQw0W/Mp92WueOOeAnVYHrvPq76J59LupGk7fil03mxQcrM4
8qL5DiocdJ5eLDTQhIVrkGjZGMfR4GeeA3YkvjXZ8Yy57PDYTB1c8a5O7OrXLXRe
BvDSFRcNMJkIlREE0+whi96VZlNfL+8/UjSzUbHDhKMzqkdgTjhaJ2aTwOv84M+3
hj5dEK8Fr9naiRjIwVdVlFRqeDAtXSK6MAV8UMCB1oFztPXGjuhTGqTmi7JmC2Uz
WJ5hD3Lh0XU2Hfyf1qXDD7TWZFL79NSTtY7c/khBDCg9hk3QimWwntkxXfoL0opk
BmVnO3h18QAErZUKGBn19YyRRUQ0ydSuvh0hDAUkPqr60zuloKGJuhjqFOCp90sX
Lm5CAvLLmOM2eRaW6a1TxzffqCleYg3NpKOX4OBhbRmg4/VNiBizzT6++3Y/8yqD
kBqp7CzVxP7y+a6J0aznc3U4V+aKLdOmOfdA5G0/29WQ+Ec5sAolnp3R9h1njYPt
sxba4Q8MG0VQyw6OZIT7Ap0tRQuYdzabKhcivn7qP6QY+NK/JFeIYiChmO9maglI
-----END RSA PRIVATE KEY-----"""


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    #Reference:https://stackoverflow.com/questions/21327491/using-pycrypto-how-to-import-a-rsa-public-key-and-use-it-to-encrypt-a-string
    
    #session_key = the encrypted session key from the client side of things. We must decrypt that using the server's private
    #key and return the AES key
    print("woopy",session_key)
    private_Key = RSA.importKey(prvkey,None)
    cipher = pkcs1.new(private_Key)
    print("kitty")
    decrypt_AES_key = cipher.decrypt(session_key,None)
    print(decrypt_AES_Key)
    return decrypt_AES_key
    


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    
    session_Key_RSA = RSA.importKey(session_key)
    cipher = Cipher_PKCS1_v1_5.new(session_Key_RSA)
    decrypted_Message = cipher.decrypt(client_message,None).decode()
    return decrypted_Message


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    
    key = RSA.importKey(session_key)
    cipher = Cipher_PKCS1_v1_5.new(encryptKey)
    cipher_message = cipher.encrypt(message.encode())
    return cipher_message


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

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                plaintext_ciphertext = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password
                print(plaintext_ciphertext)
                #message = verify_hash(user, password)

                # TODO: Encrypt response to client
                #ciphertext_response = encrypt_message(message, session_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
