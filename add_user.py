"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""
import hashlib
import binascii
import os

user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password
# reference: https://www.vitoshacademy.com/hashing-passwords-in-python/
salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt,100000)
hashed_password = binascii.hexlify(hashed_password)
hashed_password = (salt + hashed_password).decode('ascii')

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")


