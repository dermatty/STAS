#!/home/stephan/.virtualenvs/ftp0/bin/python
from Crypto.Cipher import AES
import hashlib
import io
import datetime
import os
import sys
import ftplib
import configparser
from Crypto import Random
import base64
from itertools import cycle
from functools import reduce


def FTPencrypt_and_upload(ftps, ftp_path, local_fn, fmts, key):
    # @ftsp:     ftplib descriptor
    # @ftp_fn:   file name on ftp (dest.)
    # @local_fn: file to be encrypted and uploaded to fp
    # @fmts:     fil.mod.time stamp local(os.path.getmtime(fn))
    dt0 = datetime.datetime.fromtimestamp(fmts + 1, datetime.timezone.utc)
    mfmtstr = str(dt0.year) + str(dt0.month).zfill(2) + str(dt0.day).zfill(2) + \
        str(dt0.hour).zfill(2) + str(dt0.minute).zfill(2) + str(dt0.second).zfill(2)
    # encrypt local file to bytesio
    f, s, bts = encrypt_otf(local_fn, key)
    # upload to FTP
    local_fn0 = local_fn.split("/")[-1]
    ftp_fn = ftp_path + "/" + local_fn0 + ".enc"
    ftps.storbinary("STOR " + ftp_fn, f, 1024)
    ftps.sendcmd("MFMT " + mfmtstr + " " + ftp_fn)
    f.close()


def encrypt_string(s0, key):
    data = str.encode(s0)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    bts = cipher.nonce + tag + ciphertext
    s = ""
    for b in bts:
        s += chr(b)
    return s, bts


def decrypt_string(s0, key):
    bts = b""
    for s in s0:
        bts += bytes([ord(s)])
    f = io.BytesIO(bts)
    nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data.decode())


def encrypt_otf(infile, key):
    f_in = open(infile, "rb")
    data = f_in.read(-1)
    f_in.close()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    f = io.BytesIO()
    [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    f.seek(0)
    s, bts = encrypt_string(infile, key)
    return f, s, bts


def decrypt_otf(f_in, outfile, key):
    nonce, tag, ciphertext = [f_in.read(x) for x in (16, 16, -1)]
    f_in.close()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    f_out = open(outfile, "wb")
    f_out.write(data)
    f_out.flush()
    f_out.close()


def encrypt(infile, key):
    outfile = infile + ".enc"
    f_in = open(infile, "rb")
    data = f_in.read(-1)
    f_in.close()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    f_out = open(outfile, "wb")
    [f_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    f_out.flush()
    f_out.close()


def decrypt(infile, key):
    outfile = infile[:-4]
    if infile[-4:] != ".enc":
        print("File has no extension .enc, exiting ...")
    f_in = open(infile, "rb")
    nonce, tag, ciphertext = [f_in.read(x) for x in (16, 16, -1)]
    f_in.close()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    f_out = open(outfile, "wb")
    f_out.write(data)
    f_out.flush()
    f_out.close()


def make_ascii(txt):
    sret = ""
    for t in txt:
        if ord(t) < 32 or ord(t) > 126 or t == "/":
            sret += "?"
        else:
            sret += t
    return sret


def vig_encrypt2(plain, key):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = make_ascii(plain)
    alpha_len = len(alpha)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    ciphertext = ''
    for i in range(len(plaintext_int)):
        islower = plaintext_int[i] in range(ord("a"), ord("z") + 1)
        isupper = plaintext_int[i] in range(ord("A"), ord("Z") + 1)
        if not islower and not isupper:
            ciphertext += chr(plaintext_int[i])
            continue
        ch = chr(plaintext_int[i]).upper()
        value = (ord(ch) + key_as_int[i]) % alpha_len
        if islower:
            ciphertext += alpha[value].lower()
        else:
            ciphertext += alpha[value]
    return ciphertext


def vig_decrypt2(ciphertext, key):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    alpha_len = len(alpha)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    for i in range(len(ciphertext_int)):
        islower = ciphertext_int[i] in range(ord("a"), ord("z") + 1)
        isupper = ciphertext_int[i] in range(ord("A"), ord("Z") + 1)
        if not islower and not isupper:
            plaintext += chr(ciphertext_int[i])
            continue
        ch = chr(ciphertext_int[i]).upper()
        value = (ord(ch) - key_as_int[i]) % alpha_len
        if islower:
            plaintext += alpha[value].lower()
        else:
            plaintext += alpha[value]
    return plaintext


passbyte = Random.get_random_bytes(255)
TXT = "DU deppert ### OASch DUDU!!"
KEY = make_ascii(base64.b64encode(passbyte).decode())
encrypted = vig_encrypt2(TXT, KEY)
decrypted = vig_decrypt2(encrypted, KEY)
print("KEY: ", KEY, len(KEY))
print("TXT: ", TXT)
print("-" * 50)
print(encrypted)
print(decrypted)

'''PASSWORD = "DeppDuDepp1"

# password to 16-byte key for AES via hashlib
passbyte = str.encode(PASSWORD)
hash_object = hashlib.sha256(passbyte)
hex_dig = hash_object.hexdigest()
key = str.encode(hex_dig[:16])


encrypt("photo.jpg", key)
decrypt("photo.jpg.enc", key)

s, b = encrypt_string("Hallo Welt", key)
print(s)
print(b)
decrypt_string(s, key)

f = encrypt_otf("photo.jpg", key)
decrypt_otf(f, "photo_dec.jpg", key)

SOURCEPATH = "/media/nfs/NFS_Projekte/GIT/STASFTP/data/ftptest/"
FTP_PATH = "/ftptest"
try:
    stasftpcfg = configparser.ConfigParser()
    stasftpcfg.read("../data/stasftp.cfg")
    FTP_HOST = stasftpcfg["CONFIG"]["FTP_HOST"]
    FTP_USER = stasftpcfg["CONFIG"]["FTP_USER"]
    FTP_PASSWD = stasftpcfg["CONFIG"]["FTP_PASSWD"]
except Exception as e:
    print(str(e) + ": Cannot get STASFTP config, exiting ...")
    sys.exit()

FTPS = ftplib.FTP_TLS(host=FTP_HOST, user=FTP_USER, passwd=FTP_PASSWD)
FTPS.prot_p()

local_fn = "/media/nfs/NFS_Projekte/GIT/STASFTP/bin/photo.jpg"
ftp_path = "/ftptest"
fmts = os.path.getmtime(local_fn)

FTPencrypt_and_upload(FTPS, ftp_path, local_fn, fmts, key)
'''
