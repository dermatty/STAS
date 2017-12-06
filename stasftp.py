#!/home/stephan/.virtualenvs/ftp0/bin/python

from os.path import expanduser
import ftplib
import sys
import os
import datetime
import configparser
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
import io
import time
import psutil
import argparse
import base64
import shutil
import logging
import logging.handlers
import threading

# globals
FSIZE = 0
FTRANSFERRED = 0
OUTPUT_VERBOSITY = 2
LOG_VERBOSITY = 2

GMTCOUNTER = 0

USERHOME = expanduser("~")
STASDIR = USERHOME + "/.stasftp"

EXCLUDELIST = []

UNENC_TOKEN = ".megx01"

RUNNING = False

MAXTRY = 5
SLEEPTRY = 15

# Init Logger
logger = logging.getLogger("stasftp")
logger.setLevel(logging.INFO)


# StasFTP.upload_file callback:
#    prints percentage of upload completed
def showdot(block):
    global FTRANSFERRED
    global FSIZE
    global OUTPUT_VERBOSITY
    FTRANSFERRED += 1024
    if OUTPUT_VERBOSITY < 1:
        return
    if FSIZE == 0:
        perc = 1
    else:
        perc = FTRANSFERRED/FSIZE
        if perc > 1:
            perc = 1
    print("\r", int(perc * 100), "% ", end="")


# class StasFTP:
#    handles all the FTP stuff - upload, download, cwd, ...
class StasFTP(object):
    def __init__(self, host, user, passwd):
        self.FTP_HOST = host
        self.FTP_USER = user
        self.FTP_PASSWD = passwd
        self.FTPS = None
        self.connectftp()

    def connectftp(self):
        try:
            self.FTPS = ftplib.FTP_TLS(host=self.FTP_HOST, user=self.FTP_USER, passwd=self.FTP_PASSWD, timeout=30)
            self.FTPS.prot_p()
            self.FTPS.set_pasv(True)
            self.FTP_STATUS = 0
            self.FTP_ERROR = ""
            return 0
        except Exception as e:
            self.FTP_STATUS = -1
            self.FTP_ERROR = str(e)
            return -2

    def goodbye(self):
        try:
            self.FTPS.quit()
            return 0
        except Exception as e:
            printlog(0, "Cannot quit FTP, trying to close: " + str(e))
            try:
                self.FTPS.close()
                return 0
            except Exception as e:
                printlog(0, "Cannot close, something ist wrong: " + str(e))
                return -2

    def try_reconnect(self, maxtry):
        global SLEEPTRY
        res0 = -1
        for j in range(0, maxtry):
            self.goodbye()
            printlog(1, "Performing reconnection attempt #" + str(j + 1))
            res0 = self.connectftp()
            if res0 == 0:
                try:
                    self.FTPS.voidcmd("NOOP")
                    printlog(1, "Reconnection attempt #" + str(j + 1) + " - success!")
                    return
                except:
                    if j == maxtry - 1:
                        printlog(0, "All reconnection attempts failed, exiting ...")
                        sys.exit()
            elif j == maxtry-1:
                printlog(0, "All reconnection attempts failed, exiting ...")
                sys.exit()
            printlog(1, "Reconnection failure, waiting 15 sec for next connection attempt!")
            time.sleep(SLEEPTRY)

    # wrapper around all ftp functions
    def ftp_wrapper(self, f):
        global MAXTRY
        for i in range(MAXTRY):
            # execute command
            res0 = f()        # -2 ftp error, != -2 --> return regularly else retry
            # if non-ftp error return!
            if res0 != -2:
                break
            # only try to reconnect with error=-2
            printlog(0, "Cannot complete command, FTP error!")
            if i != MAXTRY-1:
                self.try_reconnect(MAXTRY)
            else:
                printlog(0, "All reconnection attempts failed, exiting ...")
                sys.exit()
        return res0

    # modify ftp file timestamp according to local time stamp (fmts)
    def mk_utc_ftp_timestamp(self, fmts, ftp_fn):
        dt0 = datetime.datetime.fromtimestamp(fmts + 1, datetime.timezone.utc)
        mfmtstr = str(dt0.year) + str(dt0.month).zfill(2) + str(dt0.day).zfill(2) + \
            str(dt0.hour).zfill(2) + str(dt0.minute).zfill(2) + str(dt0.second).zfill(2)
        try:
            self.FTPS.sendcmd("MFMT " + mfmtstr + " " + ftp_fn)
            return mfmtstr
        except Exception as e:
            printlog(0, str(e) + ": cannot modify FTP timestamp!")
            return -2

    # upload binary file
    def upload_file(self, f, ftp_fn, fsize):
        global RUNNING
        # sign- for binary file
        try:
            self.FTPS.voidcmd('TYPE I')
        except:
            return -2
        # init socket
        try:
            sock = self.FTPS.transfercmd('STOR ' + ftp_fn)
        except Exception as e:
            printlog(0, str(e) + ": cannot initiate upload connection!")
            return -2

        def background_upload(sock, fp, res_t):
            global OUTPUT_VERBOSITY
            global RUNNING
            ftransferred = 0
            blocksize = 8192
            RUNNING = True
            while RUNNING:
                # read from infile
                try:
                    block = fp.read(blocksize)
                except Exception as e:
                    printlog(1, str(e) + ": error in infile read")
                    res_t.append(-1)
                    RUNNING = False
                    break
                if not block:
                    RUNNING = False
                    break
                # upload via socket
                try:
                    sock.sendall(block)
                except Exception as e:
                    printlog(0, str(e) + ": error in sendall to ftp")
                    res_t.append(-2)
                    RUNNING = False
                    break
                if OUTPUT_VERBOSITY < 1:
                    continue
                ftransferred += blocksize
                if fsize == 0:
                    perc = 1
                else:
                    perc = ftransferred/fsize
                if perc > 1:
                    perc = 1
                print("\r", int(perc * 100), "% uploaded", end="")
                if perc >= 1:
                    print()
            sock.close()
            res_t.append(0)

        res_thread = []
        t = threading.Thread(target=background_upload, args=(sock, f, res_thread, ))
        t.start()
        while t.is_alive():
            t.join(60)
            try:
                self.FTPS.voidcmd('NOOP')
            except Exception as e:
                RUNNING = False
                time.sleep(1)
                printlog(0, str(e) + ": cannot keepalive FTP connection during upload, killing keepalive thread")
                return -2
        try:
            self.FTPS.voidresp()
        except:
            return -2
        return res_thread[-1]

    # download binary file
    def download_file(self, ftp_fn, fsize):
        global RUNNING
        f = io.BytesIO()
        # signature for binary file
        try:
            self.FTPS.voidcmd("TYPE I")
        except:
            return -2
        # init socket
        try:
            sock = self.FTPS.transfercmd('RETR ' + ftp_fn)
        except Exception as e:
            printlog(0, str(e) + ": cannot initiate download connection!")
            return -2

        def background_download(sock, res_t):
            global OUTPUT_VERBOSITY
            global RUNNING
            RUNNING = True
            ftransferred = 0
            blocksize = 8192
            while RUNNING:
                # receive socket from ftp
                try:
                    block = sock.recv(blocksize)
                    if not block:
                        RUNNING = False
                        break
                except Exception as e:
                    printlog(0, str(e) + ": error in recv from ftp")
                    res_t.append(-2)
                    RUNNING = False
                    break
                # write file
                try:
                    f.write(block)
                except Exception as e:
                    printlog(0, str(e) + ": error in outfile write")
                    res_t.append(-1)
                    RUNNING = False
                    break
                # print fortschritt
                if OUTPUT_VERBOSITY < 1:
                    continue
                ftransferred += blocksize
                if fsize == 0:
                    perc = 1
                else:
                    perc = ftransferred/int(fsize)
                if perc > 1:
                    perc = 1
                print("\r", int(perc * 100), "% downloaded", end="")
                if perc >= 1:
                    print()
            sock.close()
            res_t.append(0)

        res_thread = []
        t = threading.Thread(target=background_download, args=(sock, res_thread, ))
        t.start()
        while t.is_alive():
            t.join(60)
            try:
                self.FTPS.voidcmd('NOOP')
            except Exception as e:
                RUNNING = False
                time.sleep(1)
                printlog(0, str(e) + ": cannot keepalive FTP connection during download, killing thread")
                return -2
        if res_thread[-1] == -1:
            f = -1
        try:
            self.FTPS.voidresp()
        except:
            return -2
        return f

    # change to ftp dir
    def cwd(self, ftpdir):
        try:
            self.FTPS.cwd(ftpdir)
            return 0
        except Exception as e:
            printlog(1, str(e) + ": cannot change to ftp dir " + ftpdir)
            if str(type(e).__name__) == "error_perm":
                return -1
            return -2

    # create new ftp dir
    def mkd(self, ftpdir, fmts):
        try:
            self.FTPS.mkd(ftpdir)
            # mfmtstr = self.mk_utc_ftp_timestamp(fmts, ftpdir + "/")
            printlog(2, "Creating new directory " + ftpdir)    # + " : " + mfmtstr)
            return 0
        except Exception as e:
            printlog(0, str(e) + " : cannot make ftp dir")
            return -2

    # get ftp dir contents, namely name, type, perm and size
    def mlsd(self, ftppath):
        try:
            a = self.FTPS.mlsd(path=ftppath, facts=["name", "type", "perm", "size"])
            return a
        except Exception as e:
            printlog(0, str(e) + ": cannot read ftp dir contents")
            return -2

    # delete file from ftp
    def delete(self, ftp_fn):
        try:
            self.FTPS.delete(ftp_fn)
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot delete file from FTP")
            print(str(type(e).__name__))
            if str(type(e).__name__) == "error_perm":
                return -1
            return -2

    # remove dir from ftp
    def rmd(self, ftpdir):
        try:
            self.FTPS.rmd(ftpdir)
            return 0, ""
        except Exception as e:
            printlog(0, str(e) + ": cannot delete directory from FTP")
            if str(type(e).__name__) == "error_perm":
                return -1
            return -2

    # convert timestamp of ftp to datetime object
    def makemtime(self, ftp_mdtm):
        fm = ftp_mdtm[4:]
        Y = int(fm[0:4])
        M = int(fm[4:6])
        D = int(fm[6:8])
        hh = int(fm[8:10])
        mm = int(fm[10:12])
        ss = int(fm[12:14])
        date = datetime.datetime(year=Y, month=M, day=D, hour=hh, minute=mm, second=ss)
        return date.replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)

    # get mod. time of ftp file as datetime object
    def get_modification_time(self, ftp_fn):
        global GMTCOUNTER
        try:
            ftp_mdtm = self.FTPS.sendcmd("MDTM " + ftp_fn)
            ret0 = self.makemtime(ftp_mdtm)
            return ret0
        except Exception as e:
            printlog(0, str(e) + ": cannot get ftp file modification time")
            if str(type(e).__name__) == "error_perm":
                return -1
            return -2


# class StasEncrypt:
#    handles all the encrypten stuff
class StasEncrypt(object):
    def __init__(self, password, vig_key, stasftp):
        self.KEY = password
        self.VIG_KEY = vig_key
        self.STASFTP = stasftp
        self.MAXMEM = psutil.virtual_memory()[0]
        self.ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    # encrypt using vigenere ciphher
    def vignere_encrypt(self, plain):
        alpha = self.ALPHA
        plaintext = make_ascii(plain)
        alpha_len = len(alpha)
        key_as_int = [ord(i) for i in self.VIG_KEY]
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

    # decrypt vignere cyper
    def vignere_decrypt(self, ciphertext):
        alpha = self.ALPHA
        alpha_len = len(alpha)
        key_as_int = [ord(i) for i in self.VIG_KEY]
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

    # AES - Opens local file and encrypts it in-mem/to BytesIO, returns file descriptor
    def encrypt_otf(self, infile):
        global STASDIR
        global UNENC_TOKEN
        # t0 = time.time()
        try:
            f_in = open(infile, "rb")
            data = f_in.read(-1)
        except Exception as e:
            printlog(0, str(e) + ": cannot open infile, returning -1")
            return -1
        try:
            f_in.close()
            printlog(2, "Encrypting " + infile)
            cipher = AES.new(self.KEY, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            printlog(2, "Encryption completed!")
            f = io.BytesIO()
            [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
            f.seek(0)
            return f, ""
        except Exception as e:
            printlog(1, str(e) + ": Error in encryption, will upload unencrypted file - " + UNENC_TOKEN)
            try:
                f = open(STASDIR + "/tmp/upload.tmp", "wb")
                f.write(data)
                f.flush()
                f.close()
                f = open(STASDIR + "/tmp/upload.tmp", "rb")
                return f, UNENC_TOKEN
            except Exception as e:
                printlog(0, str(e) + ": cannot save temp file!")
                return -1, ""

    # fallback of "Encrypt_and_uploadFTP_parallel" if not sufficient memory:
    # encrypts local files in ftp_path serially and uploads it to FTP
    def Encrypt_and_uploadtoFTP(self, ftp_path, local_fn1, fmts, fsize):
        local_fn = local_fn1
        f, suffix = self.encrypt_otf(local_fn)
        if f == -1:
            printlog(0, "Aborting encrypted file upload")
            return -1
        local_fn = local_fn + suffix
        local_fn0 = self.vignere_encrypt(local_fn.split("/")[-1])
        ftp_fn = ftp_path + "/" + local_fn0
        res0 = self.STASFTP.ftp_wrapper(lambda: self.STASFTP.upload_file(f, ftp_fn, fsize))
        f.close()
        if res0 == -1:
            printlog("Could not upload/MFMT to FTP, continuing!")
        else:
            printlog(1, "Upload of: " + local_fn + " - success")
        res0 = self.STASFTP.mk_utc_ftp_timestamp(fmts, ftp_fn)

    # AES - decrypts ftp file and write it to local file
    def decrypt_otf(self, infile, outfile, fts):
        try:
            infile.seek(0)
            nonce, tag, ciphertext = [infile.read(x) for x in (16, 16, -1)]
            infile.close()
            cipher = AES.new(self.KEY, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            f_out = open(outfile, "wb")
            f_out.write(data)
            f_out.flush()
            os.utime(outfile, (fts, fts))
            return 0
        except Exception as e:
            printlog(0, str(e) + ": decryption / file save error, returning -1")
            return -1

    # AES - Downloads file from ftp to memory, decrypts it and stores it locally
    # (local_path, local_path, ffn, fts, fsize)
    def DecryptFTP_and_download(self, local_path, fn, fts, fsize):
        global UNENC_TOKEN
        printlog(2, "Downloading from FTP to RAM: " + fn)
        f_encrypted = self.STASFTP.ftp_wrapper(lambda: self.STASFTP.download_file(fn, fsize))
        if f_encrypted == -1:
            printlog(0, "Cannot download from FTP: " + fn + ", skipping")
            return
        else:
            printlog(1, "Download of: " + fn + " - success")
        fn0 = self.vignere_decrypt(fn.split("/")[-1])
        if fn0[-len(UNENC_TOKEN):] == UNENC_TOKEN:
            printlog(2, "No decryption, file was too large for encrypted upload!")
            try:
                local_fn = local_path + "/" + fn0[:-len(UNENC_TOKEN)]
                f_out = open(local_fn, "wb")
                f_encrypted.seek(0)
                f_out.write(f_encrypted.read(-1))
                f_out.flush()
                os.utime(local_fn, (fts, fts))
                f_encrypted.close()
                f_out.close()
                printlog(1, "Unencrypted download of file " + local_fn + " successfull!")
                return
            except Exception as e:
                printlog(0, str(e) + ": Cannot download unencrypted file!")
                return
        local_fn = local_path + "/" + fn0
        printlog(2, "Decrypting from RAM and saving: " + local_fn)
        res0 = self.decrypt_otf(f_encrypted, local_fn, fts)
        f_encrypted.close()
        if res0 == 0:
            printlog(1, "Decryption + save of: " + fn + " to " + local_fn + " - success")
        else:
            printlog(0, "Cannot decrypt/save " + fn + "!")


# removes non-ascii characters from a string
def make_ascii(txt):
    sret = ""
    for t in txt:
        if ord(t) < 32 or ord(t) > 126 or t == "/":
            sret += "?"
        else:
            sret += t
    return sret


# delets recursively a ftp dir
def deleteFTPDirectoryRecursive(sftp, ftpdir):
    res = sftp.ftp_wrapper(lambda: sftp.rmd(ftpdir))
    if res == -1:   # and str(e)[:3] == "550" and str(e)[-5:] == "empty":
        printlog(1, "Changing to ftp dir " + ftpdir + " and deleting it recursivly ...")
        maindir = sftp.ftp_wrapper(lambda: sftp.mlsd(ftpdir))
        dirlist = [m for m in maindir]
        for m in dirlist:
            if m[1]["type"] == "file":
                sftp.ftp_wrapper(lambda: sftp.delete(ftpdir + "/" + m[0]))
            elif m[1]["type"] == "dir":
                deleteFTPDirectoryRecursive(sftp, ftpdir + "/" + m[0])
        sftp.ftp_wrapper(lambda: sftp.rmd(ftpdir))
    return


# remove recursively a certain char from a string's end
def remove_last_from_string_recursive(ss, ch):
    if ss[-1:] == ch:
        ss = ss[0:-1]
        s0 = remove_last_from_string_recursive(ss, ch)
        return s0
    return ss


# main algo: recursively backups local dir to ftp / restores ftp dir to local dir
def SyncLocalDir(sftp, senc, local_path, ftp_path, recursion, mode="backup"):
    global GMTCOUNTER
    global UNENC_TOKEN
    # Convention: no "/" at end of directory name
    local_path = remove_last_from_string_recursive(local_path, "/")
    ftp_path = remove_last_from_string_recursive(ftp_path, "/")
    printlog(-1, "---- Syncing FTP dir: " + ftp_path + " ----")
    printlog(2, "Recursion no. " + str(recursion))
    if mode == "backup":
        printlog(2, "Syncing local:" + local_path + " --> FTP:" + ftp_path)
        # change to FTP Dir, create directory if it does not exist
        printlog(2, "Changing FTP dir to " + ftp_path)
        res0 = sftp.ftp_wrapper(lambda: sftp.cwd(ftp_path))
        if res0 != 0:
            printlog(1, "FTP:" + ftp_path + " does not exist, creating new dir")
            sftp.ftp_wrapper(lambda: sftp.mkd(ftp_path, os.path.getmtime(local_path)))
            sftp.ftp_wrapper(lambda: sftp.cwd(ftp_path))
    elif mode == "restore":
        printlog(2, "Syncing FTP:" + ftp_path + " --> local:" + local_path)
        # create local dir if not exists
        os.makedirs(local_path, exist_ok=True)
        # change to FTP Dir
        printlog(2, "Changing FTP dir to " + ftp_path)
        sftp.ftp_wrapper(lambda: sftp.cwd(ftp_path))
    # Read FTP directory
    printlog(1, "Reading FTP directory " + ftp_path)
    ftp_listdir = sftp.ftp_wrapper(lambda: sftp.mlsd(ftp_path))
    ftp_listdir0 = sftp.ftp_wrapper(lambda: sftp.mlsd(ftp_path))
    ftp_files = [(m[0],  ftp_path + "/" + m[0], m[1]["size"], sftp.get_modification_time(ftp_path + "/" + m[0]), senc.vignere_decrypt(m[0]))
                 for m in ftp_listdir if m[1]["type"] == "file"]
    ftp_dirs = [m[0] for m in ftp_listdir0 if m[1]["type"] == "dir"]
    # Read local directory
    printlog(1, "Reading local directory " + local_path)
    try:
        dir_dirs = next(os.walk(local_path))[1]
        dir_files = next(os.walk(local_path))[2]
    except Exception as e:
        printlog(0, "Cannot list local content, exiting ...")
        return -1
    dir_file_det = []
    for df in dir_files:
        fn = local_path + "/" + df
        dir_file_det.append((df, fn, os.path.getsize(fn), os.path.getmtime(fn)))
    if mode == "backup":
        # Part Ia. compare local to ftp and update FTP files or upload (if not ye on FTP)
        printlog(1, "Uploading new/modified content ...")
        ii = 1
        for sfn0, sfn, ssize, sts in dir_file_det:
            matched = False
            sizeratio = 1
            for ffn0, ffn, fsize, fmdate, vd_ffn0 in ftp_files:
                fts = fmdate.timestamp()
                masfn0 = make_ascii(sfn0)
                if masfn0 == vd_ffn0 or vd_ffn0[0:-len(UNENC_TOKEN)] == masfn0:
                    try:
                        sizeratio = abs((int(fsize) - 30) / int(ssize) - 1)
                    except:
                        sizeratio = 0
                    matched = True
                    break
            if (matched and abs(sts - fts) > 5) or (not matched) or (matched and sizeratio > 0.2 and ssize > 1000):
                if (matched and sizeratio > 0.2 and ssize > 1000):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Incomplete file on FTP: adding " + sfn0 + " (" + str(source_ts) + ") to upload queue")
                    printlog(1, "   Size on FTP , Size on source, Ratio:" + str(fsize) + " " + str(ssize) + " " + str(sizeratio))
                    sftp.ftp_wrapper(lambda: sftp.delete(ffn))
                elif (matched and sts > fts):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Replacment because of newer: adding " + sfn0 + " (" + str(source_ts) + ") to upload queue")
                    sftp.ftp_wrapper(lambda: sftp.delete(ffn))
                else:
                    printlog(1, "New upload: adding " + sfn0 + " to FTP upload queue")
                senc.Encrypt_and_uploadtoFTP(ftp_path, sfn, sts, ssize)
            printlog(2, str(ii) + " of " + str(len(dir_file_det)) + " files processed!")
            ii += 1
    elif mode == "restore":
        # Part Ib. compare FTP to local and update local files or download (if not yet on local)
        # loop over ftp files
        printlog(1, "Downloading new/modified content ...")
        for ffn0, ffn, fsize, fmdate, vd_ffn0 in ftp_files:
            matched = False
            fts = fmdate.timestamp()
            for sfn0, sfn, ssize, sts in dir_file_det:
                masfn0 = make_ascii(sfn0)
                if vd_ffn0 == masfn0 or vd_ffn0[0:-len(UNENC_TOKEN)] == masfn0:
                    matched = True
                    break
            if (matched and abs(fts - sts) > 5):
                ftp_ts = datetime.datetime.fromtimestamp(fts)
                printlog(1, "Replacment because of newer: adding " + ffn0 + str(ftp_ts) + " to download queue")
                senc.DecryptFTP_and_download(local_path, ffn, fts, fsize)
            elif not matched:
                printlog(1, "New download: adding " + ffn0 + " to FTP download queue")
                senc.DecryptFTP_and_download(local_path, ffn, fts, fsize)
    if mode == "backup":
        # Part IIa. compare FTP to local and delete files on FTP which are not on local
        printlog(1, "Deleting locally not existing files on FTP")
        for ffn0, ffn, fsize, fmdate, vd_ffn0 in ftp_files:
            matched = False
            for sfn0, sfn, ssize, smdate in dir_file_det:
                masfn0 = make_ascii(sfn0)
                if vd_ffn0 == masfn0 or vd_ffn0[0:-len(UNENC_TOKEN)] == masfn0:
                    matched = True
                    break
            if not matched:
                printlog(1, ffn0 + " not found locally, deleting from FTP ...")
                sftp.ftp_wrapper(lambda: sftp.delete(ffn))
    elif mode == "restore":
        # Part IIb. compare local to FTP and delete files on local which are not on FTP
        printlog(1, "Deleting remotely not existing files on local drive")
        for sfn0, sfn, ssize, smdate in dir_file_det:
            matched = False
            masfn0 = make_ascii(sfn0)
            for ffn0, ffn, fsize, fmdate, vd_ffn0 in ftp_files:
                if vd_ffn0 == masfn0 or vd_ffn0[0:-len(UNENC_TOKEN)] == masfn0:
                    matched = True
                    break
            if not matched:
                printlog(1, sfn0 + " not found on FTP, deleting locally ...")
                os.remove(sfn)
    if mode == "backup":
        # Part IIIa. compare FTP dirs to local dirs and delete dirs on FTP which are not local
        printlog(2, "Deleting locally not exisiting dirs on FTP")
        asc_dirs = [make_ascii(d) for d in dir_dirs]
        for fd0 in ftp_dirs:
            fd00 = senc.vignere_decrypt(fd0)
            if fd00 == -1 or fd00 not in asc_dirs:
                printlog(1, "Directory " + ftp_path + "/" + fd0 + " not found locally, deleting from FTP ...")
                deleteFTPDirectoryRecursive(sftp, ftp_path + "/" + fd0)
    elif mode == "restore":
        printlog(1, "Deleting remotely not existing dirs on local drive")
        # Part IIIb. compare local dirs to FTP dirs and delete local dirs which are not on FTP
        for sd0 in dir_dirs:
            matched = False
            for fd0 in ftp_dirs:
                fd00 = senc.vignere_decrypt(fd0)
                if make_ascii(sd0) == fd00:
                    matched = True
                    break
            if not matched:
                printlog(1, "Directory " + local_path + "/" + sd0 + " not found on FTP, deleting locally ...")
                shutil.rmtree(local_path + "/" + sd0)
    # recursion to other directories
    if mode == "backup":
        dirlist = dir_dirs
    elif mode == "restore":
        dirlist = ftp_dirs
    for dd in dirlist:
        if mode == "backup":
            tryld1 = local_path + "/" + dd
            tryld2 = local_path + "/" + dd + "/"
        else:
            tryld1 = local_path + "/" + senc.vignere_decrypt(dd)
            tryld2 = local_path + "/" + senc.vignere_decrypt(dd) + "/"
        if tryld1 in EXCLUDELIST or tryld2 in EXCLUDELIST:
            printlog(1, "Excluding local directory: " + tryld1)
            continue
        if mode == "backup":
            dd0 = senc.vignere_encrypt(dd)
            for ff in ftp_dirs:
                if senc.vignere_decrypt(ff) == dd:
                    dd0 = ff
                    break
            SyncLocalDir(sftp, senc, local_path + "/" + dd, ftp_path + "/" + dd0, recursion + 1, mode=mode)
        elif mode == "restore":
            SyncLocalDir(sftp, senc, local_path + "/" + senc.vignere_decrypt(dd), ftp_path + "/" + dd, recursion + 1, mode=mode)


# aux. routine for output and logs
def printlog(level, msg):
    global OUTPUT_VERBOSITY
    global logger
    # level 0: critical , level 2: all
    if level <= OUTPUT_VERBOSITY:
        if level == 0:
            msg = "!ERROR: " + msg
        print(msg)
    # logging
    if level <= LOG_VERBOSITY:
        if level == 0:
            logger.error(msg)
        elif level == -1 or level == 1 or level == 2:
            logger.info(msg)


def os_touch(path):
    try:
        with open(path, 'a'):
            os.utime(path, None)
    except Exception as e:
        print(str(e) + " " + path)


# main
if __name__ == "__main__":
    # check for .stasftp directory and subdirectories
    if not os.path.isdir(STASDIR):
        try:
            os.makedirs(STASDIR)
            time.sleep(0.1)
            os.makedirs(STASDIR + "/keys")
            os.makedirs(STASDIR + "/config")
            os.makedirs(STASDIR + "/exclude")
            os.makedirs(STASDIR + "/log")
            os.makedirs(STASDIR + "/tmp")
            os_touch(STASDIR + "/config/stasftp.cfg")
            printlog(1, "Basic directory structure created, now please fill it with content ... ;-)")
            sys.exit()
        except Exception as e:
            printlog(0, str(e) + ": cannot create stasftp directory structure, exiting")
            sys.exit()

    # read arguments -l -r -m -c
    parser = argparse.ArgumentParser(description='AES encrypted FTP backup/restore tool')
    parser.add_argument('-l', "--local", help='/path/to/local_directory', type=str)
    parser.add_argument('-r', "--remote", help='/remote/directory/on_FTP_server', type=str)
    parser.add_argument('-m', "--mode", help='backup <-> restore', type=str)
    parser.add_argument('-o', "--log", help='name of logfile (in ~/.stasftp/logs/)', type=str)
    parser.add_argument('-e', "--exclude", help='name of excludefile (in ~/.stasftp/exclude/)', type=str)
    args = parser.parse_args()
    if args.local is None:
        printlog(0, "--local : /path/to/local_directory has to be provided, exiting ...")
        sys.exit()
    else:
        SOURCEPATH = args.local
    if args.remote is None:
        printlog(0, "--remote : /remote/directory/on_FTP_server has to be provided")
        sys.exit()
    else:
        FTP_PATH = args.remote
    if args.mode is None:
        printlog(0, "--mode : info about backup / restore has to be provided")
        sys.exit()
    else:
        STASMODE = args.mode
        if STASMODE not in ["backup", "restore"]:
            printlog(0, "Mode has to be 'backup' or 'restore', exiting ...")
            sys.exit()
    if args.log is None:
        try:
            fh = logging.FileHandler(STASDIR + "/log/stasftp.log", mode="w")
        except:
            printlog(0, "Please either create default log dir ~/.stasftp/log and/or provide -o parameter, exiting")
            sys.exit()
    else:
        try:
            fh = logging.FileHandler(STASDIR + "/log/" + args.log, mode="w")
        except:
            printlog(0, "Cannot set log path, changing to default")
            printlog(0, "Please provide correct -o parameter, exiting")
            sys.exit()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if args.exclude is None:
        EXCLUDELIST = []
    else:
        try:
            exf = open(STASDIR + "/exclude/" + args.exclude, "r")
            for exf0 in exf:
                EXCLUDELIST.append(exf0.rstrip())
            exf.close()
        except:
            printlog(0, "Please provide reasonable exclude file, exiting")
            sys.exit()
    # read config file
    try:
        STASCFGPATH = STASDIR + "/config/"
        stasftpcfg = configparser.ConfigParser()
        stasftpcfg.read(STASCFGPATH + "stasftp.cfg")
        FTP_HOST = stasftpcfg["CONFIG"]["FTP_HOST"]
        FTP_USER = stasftpcfg["CONFIG"]["FTP_USER"]
        FTP_PASSWD = stasftpcfg["CONFIG"]["FTP_PASSWD"]
        try:
            OUTPUT_VERBOSITY = int(stasftpcfg["LOG"]["OUTPUT_VERBOSITY"])
            LOG_VERBOSITY = int(stasftpcfg["LOG"]["LOG_VERBOSITY"])
        except:
            OUTPUT_VERBOSITY = 2
            LOG_VERBOSITY = 2
    except Exception as e:
        printlog(0, str(e) + ": Cannot get (complete) STASFTP config, exiting ...")
        sys.exit()
    # import / generate AES_key file
    try:
        KEY_PASSWD = base64.b64decode(open(STASDIR + "/keys/AES_key", "rb").read())
        printlog(2, "Read key from AES_key file successfull!")
    except Exception as e:
        if STASMODE == "restore":
            printlog(2, "AES_key file cannot be found, please provide AES key file!")
            sys.exit()
        passbyte = Random.get_random_bytes(32)
        iterations = 5000
        salt = os.urandom(32)
        KEY_PASSWD = PBKDF2(passbyte, salt, dkLen=16, count=iterations)
        encoded_passwd = base64.b64encode(KEY_PASSWD)
        f = open(STASCFGPATH + "AES_key", "wb")
        f.write(encoded_passwd)
        f.close()
        printlog(2, "No AES_key file found, generated new key and saved in file.")
    # import / generate VIGENERE_key file
    try:
        encoded_vig_pw = open(STASDIR + "/keys/VIGENERE_key", "rb").read()
        printlog(2, "Read key from VIGENERE_key file successfull!")
    except Exception as e:
        if STASMODE == "restore":
            printlog(2, "VIGENERE_key file cannot be found, please provide VIGENERE key file!")
            sys.exit()
        passbyte = Random.get_random_bytes(255)
        iterations = 5000
        salt = os.urandom(32)
        vignere_passw = PBKDF2(passbyte, salt, dkLen=255, count=iterations)
        encoded_vig_pw = base64.b64encode(vignere_passw)
        f = open(STASCFGPATH + "VIGENERE_key", "wb")
        f.write(encoded_vig_pw)
        f.close()
        printlog(2, "No VIGENERE_key file found, generated new key and saved in file.")
    VIGENERE_KEY = make_ascii(encoded_vig_pw.decode())
    # invoke sftp and senc object and call main algo
    sftp = StasFTP(FTP_HOST, FTP_USER, FTP_PASSWD)
    if sftp.FTP_STATUS == -1:
        printlog(0, sftp.FTP_ERROR + ": FTP connection error, exiting ...")
        sys.exit()
    else:
        printlog(2, "FTP '" + sftp.FTP_HOST + "' connected!")
    senc = StasEncrypt(KEY_PASSWD, VIGENERE_KEY, sftp)
    t0 = time.time()
    res0 = SyncLocalDir(sftp, senc, SOURCEPATH, FTP_PATH, 1, mode=STASMODE)
    if res0 == -1:
        printlog(0, "Sync not completed!")
    else:
        printlog(1, "Sync completed in " + str(time.time() - t0) + " sec.!")
