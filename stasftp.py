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
from multiprocessing import Pool, cpu_count
import psutil
import argparse
import base64
import shutil
import logging
import logging.handlers

# globals
FSIZE = 0
FTRANSFERRED = 0
OUTPUT_VERBOSITY = 2
LOG_VERBOSITY = 2
PARALLEL = False

USERHOME = expanduser("~")

# Init Logger
logger = logging.getLogger("stasftp")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(USERHOME + "/logs/stasftp.log", mode="w")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)


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
        try:
            self.FTP_HOST = host
            self.FTP_USER = user
            self.FTP_PASSWD = passwd
            self.FTPS = ftplib.FTP_TLS(host=self.FTP_HOST, user=self.FTP_USER, passwd=self.FTP_PASSWD)
            self.FTPS.prot_p()
        except Exception as e:
            self.FTP_STATUS = -1
            self.FTP_ERROR = str(e)
        self.FTP_STATUS = 0
        self.FTP_ERROR = "N/A"

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
            return -1

    # upload binary file
    def upload_file(self, f, ftp_fn, fsize):
        global FSIZE
        global FTRANSFERRED
        FSIZE = fsize
        FTRANSFERRED = 0
        try:
            self.FTPS.storbinary("STOR " + ftp_fn, f, callback=showdot, blocksize=1024)
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot upload file!")
            return -1

    # download binary file to mem/BytesIO
    def download_file(self, ftp_fn, fsize):
        # downloads file to bytesIO
        f = io.BytesIO()
        try:
            self.FTPS.retrbinary("RETR " + ftp_fn, f.write)
            f.seek(0)
            return f
        except Exception as e:
            printlog(0, str(e) + ": cannot download / store FTP file " + ftp_fn)
            return -1

    # change to ftp dir
    def cwd(self, ftpdir):
        try:
            self.FTPS.cwd(ftpdir)
            return 0
        except Exception as e:
            printlog(1, str(e) + ": cannot change to ftp_dir " + ftpdir)
            return -1

    # create new ftp dir
    def mkd(self, ftpdir, fmts):
        try:
            self.FTPS.mkd(ftpdir)
            # mfmtstr = self.mk_utc_ftp_timestamp(fmts, ftpdir + "/")
            printlog(2, "Creating new directory " + ftpdir)    # + " : " + mfmtstr)
            return 0
        except Exception as e:
            printlog(0, str(e) + " : exiting ...")
            return -1

    # get ftp dir contents, namely name, type, perm and size
    def mlsd(self, ftppath):
        try:
            return self.FTPS.mlsd(path=ftppath, facts=["name", "type", "perm", "size"])
        except Exception as e:
            printlog(0, str(e) + ": cannot read ftp directory content")
            return -1

    # delete file from ftp
    def delete(self, ftp_fn):
        try:
            self.FTPS.delete(ftp_fn)
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot delete file from FTP")
            return -1

    # remove dir from ftp
    def rmd(self, ftpdir):
        try:
            self.FTPS.rmd(ftpdir)
            return 0, ""
        except Exception as e:
            printlog(0, str(e) + ": cannot delete directory from FTP")
            return -1, str(e)

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
        try:
            ftp_mdtm = self.FTPS.sendcmd("MDTM " + ftp_fn)
            return self.makemtime(ftp_mdtm)
        except Exception as e:
            printlog(0, str(e) + ": cannot get ftp file modification time")
            return -1


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
        t0 = time.time()
        try:
            f_in = open(infile, "rb")
            data = f_in.read(-1)
        except Exception as e:
            printlog(0, str(e) + ": cannot open infile, returning -1")
            return -1
        f_in.close()
        cipher = AES.new(self.KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        f = io.BytesIO()
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
        f.seek(0)
        printlog(2, "---->" + str(time.time() - t0))
        return f
    
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
    def DecryptFTP_and_download(self, stasftp, local_path, downloadlist):
        if not downloadlist:
            return 0
        for d in downloadlist:
            fn, fts, key, fsize = d
            printlog(2, "Downloading from FTP to RAM: " + fn)
            f_encrypted = stasftp.download_file(fn, fsize)
            if f_encrypted == -1:
                printlog(0, "Cannot download from FTP: " + fn + ", skipping")
                continue
            else:
                printlog(1, "Download of: " + fn + " - success")
            fn0 = self.vignere_decrypt(fn.split("/")[-1])
            local_fn = local_path + "/" + fn0
            printlog(2, "Decrypting from RAM and saving: " + local_fn)
            res0 = self.decrypt_otf(f_encrypted, local_fn, fts)
            f_encrypted.close()
            if res0 == 0:
                printlog(1, "Decryption + save of: " + fn + " to " + local_fn + " - success")
            else:
                printlog(0, "Cannot decrypt/save " + fn + "!")

    # AES - Encrypts files in ftp_path to memory in parallel if possible and uploads it to ftp
    def Encrypt_and_uploadFTP_parallel(self, stasftp, ftp_path, uploadlist):
        global PARALLEL
        if not uploadlist:
            return 0
        printlog(2, "Checking for sufficient memory for parallel encryption")
        freemem = psutil.virtual_memory()[1]
        neededmem = sum([sz for (_, _, _, sz) in uploadlist])
        printlog(2, "Free:" + str(freemem) + ", Needed: " + str(neededmem))
        if neededmem * 1.15 > freemem or not PARALLEL:
            # printlog(1, "Not enough free RAM for parallel encryption, switching to serial encryption ...")
            for u in uploadlist:
                fn, ts, _, fs = u
                res = self.Encrypt_and_uploadtoFTP(ftp_path, fn, ts, fs)
            return res
        printlog(1, "Starting parallel encryption of " + str(len(uploadlist)) + " files")
        t0 = time.time()
        with Pool(cpu_count()) as p:
            flist = p.map(encrypt_otf_standalone, uploadlist)
        printlog(2, "Encryption took " + str(time.time() - t0) + " sec.")
        for f, local_fn, fmts, fsize in flist:
            local_fn0 = self.vignere_encrypt(local_fn.split("/")[-1])
            ftp_fn = ftp_path + "/" + local_fn0
            if f == -1:
                printlog(2, "Skipping upload of file " + local_fn0)
            try:
                printlog(2, "Uploading " + ftp_fn + " to FTP: ")
                res0 = stasftp.upload_file(f, ftp_fn, fsize)
                f.close()
                if res0 == -1:
                    raise("FTP upload error")
                else:
                    printlog(1, "Upload of: " + local_fn + " - success")
                res0 = stasftp.mk_utc_ftp_timestamp(fmts, ftp_fn)
                if res0 == -1:
                    raise("FTP MFMT error")
            except Exception as e:
                printlog(0, str(e) + ": upload/MFMT to FTP failed!")
        return 0

    # fallback of "Encrypt_and_uploadFTP_parallel" if not sufficient memory:
    # encrypts local files in ftp_path serially and uploads it to FTP
    def Encrypt_and_uploadtoFTP(self, ftp_path, local_fn, fmts, fsize):
        f = self.encrypt_otf(local_fn)
        if f == -1:
            printlog(0, "Aborting encrypted file upload")
            return -1
        local_fn0 = self.vignere_encrypt(local_fn.split("/")[-1])
        ftp_fn = ftp_path + "/" + local_fn0
        try:
            res0 = self.STASFTP.upload_file(f, ftp_fn, fsize)
            f.close()
            if res0 == -1:
                raise("FTP upload error")
            else:
                printlog(1, "Upload of: " + local_fn + " - success")
            res0 = self.STASFTP.mk_utc_ftp_timestamp(fmts, ftp_fn)
            if res0 == -1:
                raise("FTP MFMT error")
            return 0
        except Exception as e:
            printlog(0, str(e) + ": upload/MFMT to FTP failed!")
            return -1


# this is called by parallel processing pool for "Encrypt_and_uploadFTP_parallel" above
def encrypt_otf_standalone(param):
        infile, timestamp, key, fsize = param
        try:
            f_in = open(infile, "rb")
            data = f_in.read(-1)
        except Exception as e:
            printlog(0, str(e) + ": cannot open infile, returning -1")
            return -1
        f_in.close()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        f = io.BytesIO()
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
        f.seek(0)
        return f, infile, timestamp, fsize


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
    res, e = sftp.rmd(ftpdir)
    if res == -1 and str(e)[:3] == "550" and str(e)[-5:] == "empty":
        printlog(1, "Changing to ftp dir " + ftpdir + " and deleting it recursivly ...")
        maindir = sftp.mlsd(ftpdir)
        dirlist = [m for m in maindir]
        for m in dirlist:
            if m[1]["type"] == "file":
                sftp.delete(ftpdir + "/" + m[0])
            elif m[1]["type"] == "dir":
                deleteFTPDirectoryRecursive(sftp, ftpdir + "/" + m[0])
        sftp.rmd(ftpdir)
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
    # Convention: no "/" at end of directory name
    local_path = remove_last_from_string_recursive(local_path, "/")
    ftp_path = remove_last_from_string_recursive(ftp_path, "/")
    printlog(2, "---- RECURSION " + str(recursion) + " " + "-" * 100)
    if mode == "backup":
        printlog(2, "Syncing local:" + local_path + " --> FTP:" + ftp_path)
        # change to FTP Dir, create directory if it does not exist
        printlog(2, "Changing FTP dir to " + ftp_path)
        res0 = sftp.cwd(ftp_path)
        if res0 == -1:
            printlog(1, "FTP:" + ftp_path + " does not exit, creating new dir")
            res1 = sftp.mkd(ftp_path, os.path.getmtime(local_path))
            if res1 == 0:
                res2 = sftp.cwd(ftp_path)
                if res2 == -1:
                    printlog(0, "Cannot change to new ftp dir, aborting ...")
                    return -1
            else:
                printlog(0, "Cannot create new ftp dir, aborting ...")
                return -1
    elif mode == "restore":
        printlog(2, "Syncing FTP:" + ftp_path + " --> local:" + local_path)
        # create local dir if not exists
        os.makedirs(local_path, exist_ok=True)
        # change to FTP Dir, create directory if it does not exist
        printlog(2, "Changing FTP dir to " + ftp_path)
        res0 = sftp.cwd(ftp_path)
        if res0 == -1:
            printlog(0, "Cannot change to path " + ftp_path + " on FTP, exiting ...")
            sys.exit()
    # Read FTP directory
    ftp_listdir = sftp.mlsd(ftp_path)
    ftp_listdir0 = sftp.mlsd(ftp_path)
    if ftp_listdir == -1 or ftp_listdir0 == -1:
        printlog(0, "Cannot list ftp directory content, aborting ...")
        return -1
    ftp_files = [(m[0],  ftp_path + "/" + m[0], m[1]["size"], sftp.get_modification_time(ftp_path + "/" + m[0]))
                 for m in ftp_listdir if m[1]["type"] == "file"]
    ftp_dirs = [m[0] for m in ftp_listdir0 if m[1]["type"] == "dir"]
    printlog(2, "FTP files: " + ftp_path)
    for (dfd_fn0, dfd_fn, dfd_size, dfd_mdate) in ftp_files:
        printlog(2, "  " + dfd_fn0 + " : " + dfd_fn + " : " + str(dfd_mdate) + " : " + str(dfd_size))
    printlog(2, "FTP directories:" + ftp_path)
    for m in ftp_dirs:
        printlog(2, "  " + m)
    # Read local directory
    dir_dirs = next(os.walk(local_path))[1]
    dir_files = next(os.walk(local_path))[2]
    dir_file_det = []
    for df in dir_files:
        fn = local_path + "/" + df
        dir_file_det.append((df, fn, os.path.getsize(fn), os.path.getmtime(fn)))
    if dir_file_det:
        printlog(2, "Local files: " + local_path)
        for (dfd_fn0, dfd_fn, dfd_size, dfd_mdate) in dir_file_det:
            printlog(2, "  " + dfd_fn0 + " : " + dfd_fn + " : " + str(dfd_mdate) + " : " + str(dfd_size))
    if dir_dirs:
        printlog(2, "Local directories: " + local_path)
        for d in dir_dirs:
            printlog(2, "  " + d)
    if mode == "backup":
        # Part Ia. compare local to ftp and update FTP files or upload (if not ye on FTP)
        uploadlist = []
        for sfn0, sfn, ssize, sts in dir_file_det:
            matched = False
            sizeratio = 1
            for ffn0, ffn, fsize, fmdate in ftp_files:
                fts = fmdate.timestamp()
                if make_ascii(sfn0) == senc.vignere_decrypt(ffn0):
                    try:
                        sizeratio = abs((int(fsize) - 30) / int(ssize) - 1)
                    except:
                        sizeratio = 0
                    matched = True
                    break
            if (matched and sts > fts) or (not matched) or (matched and sizeratio > 0.2 and ssize > 1000):
                if (matched and sizeratio > 0.2 and ssize > 1000):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Incomplete file on FTP: adding " + sfn0 + " (" + str(source_ts) + ") to upload queue")
                    printlog(1, "   Size on FTP , Size on source, Ratio:" + str(fsize) + " " + str(ssize) + " " + str(sizeratio))
                    sftp.delete(ffn)
                elif (matched and sts > fts):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Replacment because of newer: adding " + sfn0 + " (" + str(source_ts) + ") to upload queue")
                    sftp.delete(ffn)
                else:
                    printlog(1, "New upload: adding " + sfn0 + " to FTP upload queue")
                uploadlist.append((sfn, sts, senc.KEY, ssize))
        senc.Encrypt_and_uploadFTP_parallel(sftp, ftp_path, uploadlist)
    elif mode == "restore":
        # Part Ib. compare FTP to local and update local files or download (if not yet on local)
        downloadlist = []
        # loop over ftp files
        for ffn0, ffn, fsize, fmdate in ftp_files:
            matched = False
            fts = fmdate.timestamp()
            for sfn0, sfn, ssize, sts in dir_file_det:
                if make_ascii(sfn0) == senc.vignere_decrypt(ffn0):
                    matched = True
                    break
            if (matched and fts > sts):
                ftp_ts = datetime.datetime.fromtimestamp(fts)
                printlog(1, "Replacment because of newer: adding", ffn0, ftp_ts, " to download queue")
                downloadlist.append((ffn, fts, senc.KEY, fsize))
            elif not matched:
                printlog(1, "New download: adding " + ffn0 + " to FTP download queue")
                downloadlist.append((ffn, fts, senc.KEY, fsize))
        senc.DecryptFTP_and_download(sftp, local_path, downloadlist)
    if mode == "backup":
        # Part IIa. compare FTP to local and delete files on FTP which are not on local
        for ffn0, ffn, fsize, fmdate in ftp_files:
            matched = False
            for sfn0, sfn, ssize, smdate in dir_file_det:
                if senc.vignere_decrypt(ffn0) == make_ascii(sfn0):
                    matched = True
                    break
            if not matched:
                printlog(1, ffn0 + " not found locally, deleting from FTP ...")
                sftp.delete(ffn)
    elif mode == "restore":
        # Part IIb. compare local to FTP and delete files on local which are not on FTP
        for sfn0, sfn, ssize, smdate in dir_file_det:
            matched = False
            for ffn0, ffn, fsize, fmdate in ftp_files:
                if senc.vignere_decrypt(ffn0) == make_ascii(sfn0):
                    matched = True
                    break
            if not matched:
                printlog(1, sfn0 + " not found on FTP, deleting locally ...")
                os.remove(sfn)
    if mode == "backup":
        # Part IIIa. compare FTP dirs to local dirs and delete dirs on FTP which are not local
        asc_dirs = [make_ascii(d) for d in dir_dirs]
        for fd0 in ftp_dirs:
            fd00 = senc.vignere_decrypt(fd0)
            if fd00 == -1 or fd00 not in asc_dirs:
                printlog(1, "Directory " + ftp_path + "/" + fd0 + " not found locally, deleting from FTP ...")
                deleteFTPDirectoryRecursive(sftp, ftp_path + "/" + fd0)
    elif mode == "restore":
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
    # level 0: critical , level 2: all
    if level <= OUTPUT_VERBOSITY:
        if level == 0:
            msg = "!ERROR: " + msg
        print(msg)
    # logging
    if level <= LOG_VERBOSITY:
        if level == 0:
            logger.error(msg)
        elif level == 1 or level == 2:
            logger.info(msg)


# main
if __name__ == "__main__":
    # read arguments -l -r -m -c
    parser = argparse.ArgumentParser(description='AES encrypted FTP backup/restore tool')
    parser.add_argument('-l', "--local", help='/path/to/local_directory', type=str)
    parser.add_argument('-r', "--remote", help='/remote/directory/on_FTP_server', type=str)
    parser.add_argument('-m', "--mode", help='backup <-> restore', type=str)
    parser.add_argument('-p', "--parallel", help='yes/no: enables parallel encryption', type=str)
    parser.add_argument('-c', "--config", help='/path/to/config ', type=str)
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
    if args.config is None:
        STASCFGPATH = USERHOME + "/.config/stasftp/"
    else:
        STASCFGPATH = args.mode
    if args.parallel is None or args.parallel.lower() == "no":
        PARALLEL = False
    elif args.parallel.lower() == "yes":
        PARALLEL = True
    if PARALLEL:
        printlog(2, "Parallel encryption enabled!")
    else:
        printlog(2, "Parallel encryption disabled!")
    # read config file
    try:
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
        KEY_PASSWD = base64.b64decode(open(STASCFGPATH + "AES_key", "rb").read())
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
        encoded_vig_pw = open(STASCFGPATH + "VIGENERE_key", "rb").read()
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
    SyncLocalDir(sftp, senc, SOURCEPATH, FTP_PATH, 1, mode=STASMODE)
    printlog(1, "Sync completed!")
