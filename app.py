from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys
import base64

def generate_key(password):
    password = password.encode("UTF-8")
    length = bytes(len(password))
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=length,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(path, password):
    key = generate_key(password)
    #print(key)
    f = Fernet(key)
    data = f.encrypt(path)
    return data

def decrypt_file(path, password):
    key = generate_key(password)
    #print(key)
    f = Fernet(key)
    data = f.decrypt(path)
    return data

path = sys.argv[1]
cmd = sys.argv[2].upper()
password = sys.argv[3]

#edata = encrypt_file(path, password)
#ddata = decrypt_file(edata, password)

#print(edata)
#print(ddata)

if cmd == "E":
    R = bytes(open(path, "r").read(), "utf-8")
    data = encrypt_file(R, password)
    data = data.decode("utf-8")
    W = open(path, "w")
    W.write(data)
    W.close()
    print(data)
elif cmd == "D":
    R = bytes(open(path, "r").read(), "utf-8")
    data = decrypt_file(R, password)
    W = open(path, "w")
    W.write(data.decode("utf-8"))
    W.close()
    print(data)
else:
    print("Wrong Arguments!")