#!/home/stephan/.virtualenvs/ftp0/bin/python

# STASFTP
# FTP backup script, which encrypts local files on the fly before
# uploading them to FTP
# Licensed under GPLv3


import ftplib
import sys
import os
import datetime
import configparser
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from cryptography.fernet import Fernet
# import hashlib
import io
import time
from multiprocessing import Pool, cpu_count
import psutil
import argparse
import base64
import shutil


FSIZE = 0
FTRANSFERRED = 0
OUTPUT_VERBOSITY = 2
LOG_VERBOSITY = 2


def showdot(block):
    global FTRANSFERRED
    global FSIZE
    FTRANSFERRED += 1024
    if FSIZE == 0:
        perc = 1
    else:
        perc = FTRANSFERRED/FSIZE
        if perc > 1:
            perc = 1
    print("\r", int(perc * 100), "% ", end="")


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
        # @fmts:    fil.mod.time stamp local(os.path.getmtime(local_fn))
        dt0 = datetime.datetime.fromtimestamp(fmts + 1, datetime.timezone.utc)
        mfmtstr = str(dt0.year) + str(dt0.month).zfill(2) + str(dt0.day).zfill(2) + \
            str(dt0.hour).zfill(2) + str(dt0.minute).zfill(2) + str(dt0.second).zfill(2)
        try:
            self.FTPS.sendcmd("MFMT " + mfmtstr + " " + ftp_fn)
            return mfmtstr
        except Exception as e:
            printlog(0, str(e) + ": cannot modify FTP timestamp!")
            return -1

    def upload_file(self, f, ftp_fn, fsize):
        global FSIZE
        global FTRANSFERRED
        FSIZE = fsize
        FTRANSFERRED = 0
        try:
            self.FTPS.storbinary("STOR " + ftp_fn, f, callback=showdot, blocksize=1024)
            printlog(2, "- success!")
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot upload file!")
            return -1

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

    def cwd(self, ftpdir):
        try:
            self.FTPS.cwd(ftpdir)
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot change to ftp_dir " + ftpdir)
            return -1

    def mkd(self, ftpdir, fmts):
        try:
            self.FTPS.mkd(ftpdir)
            # mfmtstr = self.mk_utc_ftp_timestamp(fmts, ftpdir + "/")
            print("**** Creating new directory " + ftpdir)    # + " : " + mfmtstr)
            return 0
        except Exception as e:
            printlog(0, str(e) + " : exiting ...")
            return -1

    def mlsd(self, ftppath):
        try:
            return self.FTPS.mlsd(path=ftppath, facts=["name", "type", "perm", "size"])
        except Exception as e:
            printlog(0, str(e) + ": cannot read ftp directory content")
            return -1

    def delete(self, ftp_fn):
        try:
            self.FTPS.delete(ftp_fn)
            return 0
        except Exception as e:
            printlog(0, str(e) + ": cannot delete file from FTP")
            return -1

    def rmd(self, ftpdir):
        try:
            self.FTPS.rmd(ftpdir)
            return 0, ""
        except Exception as e:
            printlog(0, str(e) + ": cannot delete directory from FTP")
            return -1, str(e)

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

    def get_modification_time(self, ftp_fn):
        try:
            ftp_mdtm = self.FTPS.sendcmd("MDTM " + ftp_fn)
            return self.makemtime(ftp_mdtm)
        except Exception as e:
            printlog(0, str(e) + ": cannot get ftp file modification time")
            return -1


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


class StasEncrypt(object):
    def __init__(self, password, stasftp):
        self.KEY = password
        self.STASFTP = stasftp
        self.MAXMEM = psutil.virtual_memory()[0]

    # in theory a file name encryption can be implemented here ... didnt find on so far
    def fernet_encrypt(self, s):
        return s + ".enc"

    # in theory a file name decryption can be implemented here ... didnt find on so far
    def fernet_decrypt(self, s):
        if s.endswith('.enc'):
            s = s[:-4]
        return s

    # Opens (local) @infile and encrypts it to BytesIO, returns file descriptor
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
        print("---->", time.time() - t0)
        return f

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
            fn0 = self.fernet_decrypt(fn.split("/")[-1])
            local_fn = local_path + "/" + fn0
            printlog(2, "Decrypting from RAM and saving: " + local_fn)
            self.decrypt_otf(f_encrypted, local_fn, fts)
            f_encrypted.close()

    def Encrypt_and_uploadFTP_parallel(self, stasftp, ftp_path, uploadlist):
        if not uploadlist:
            return 0
        printlog(2, "Checking for sufficient memory for parallel encryption")
        freemem = psutil.virtual_memory()[1]
        neededmem = sum([sz for (_, _, _, sz) in uploadlist])
        printlog(2, "Free:" + str(freemem) + ", Needed: " + str(neededmem))
        if neededmem * 1.15 > freemem:
            printlog(1, "Not enough free RAM for parallel encryption, switching to serial encryption ...")
            for u in uploadlist:
                fn, ts, _, _ = u
                res = self.Encrypt_and_uploadtoFTP(ftp_path, fn, ts)
            return res
        printlog(1, "Starting parallel encryption of " + str(len(uploadlist)) + " files")
        t0 = time.time()
        with Pool(cpu_count()) as p:
            flist = p.map(encrypt_otf_standalone, uploadlist)
        printlog(2, "Encryption took " + str(time.time() - t0) + " sec.")
        for f, local_fn, fmts, fsize in flist:
            local_fn0 = self.fernet_encrypt(local_fn.split("/")[-1])
            ftp_fn = ftp_path + "/" + local_fn0
            if f == -1:
                printlog(2, "Skipping upload of file " + local_fn0)
            try:
                printlog(2, "Uploading " + ftp_fn + " to FTP: ")
                res0 = stasftp.upload_file(f, ftp_fn, fsize)
                f.close()
                if res0 == -1:
                    raise("FTP upload error")
                res0 = stasftp.mk_utc_ftp_timestamp(fmts, ftp_fn)
                if res0 == -1:
                    raise("FTP MFMT error")
            except Exception as e:
                printlog(0, str(e) + ": upload/MFMT to FTP failed!")
        return 0

    # Encrypts local file and uploads it to FTP
    def Encrypt_and_uploadtoFTP(self, ftp_path, local_fn, fmts):
        # @ftps:       ftplib descriptor
        # @ftp_path:   file name on ftp (dest.)
        # @local_fn:   file to be encrypted and uploaded to fp
        # @fmts:       fil.mod.time stamp local(os.path.getmtime(fn))
        # encrypt local file to bytesio
        f = self.encrypt_otf(local_fn)
        if f == -1:
            print("Aborting encrypted file upload")
            return -1
        # upload to FTP
        local_fn0 = self.fernet_encrypt(local_fn.split("/")[-1])
        ftp_fn = ftp_path + "/" + local_fn0
        try:
            res0 = self.STASFTP.upload_file(f, ftp_fn)
            f.close()
            if res0 == -1:
                raise("FTP upload error")
            res0 = self.STASFTP.mk_utc_ftp_timestamp(fmts, ftp_fn)
            if res0 == -1:
                raise("FTP MFMT error")
            return 0
        except Exception as e:
            printlog(0, str(e) + ": upload/MFMT to FTP failed!")
            return -1


def deleteFTPDirectoryRecursive(sftp, ftpdir):
    res, e = sftp.rmd(ftpdir)
    if res == -1 and str(e)[:3] == "550" and str(e)[-5:] == "empty":
        maindir = sftp.mlsd(ftpdir)
        dirlist = [m for m in maindir]
        for m in dirlist:
            if m[1]["type"] == "file":
                sftp.delete(ftpdir + "/" + m[0])
            elif m[1]["type"] == "dir":
                deleteFTPDirectoryRecursive(sftp, ftpdir + "/" + m[0])
        sftp.rmd(ftpdir)
    return


def remove_last_from_string_recursive(ss, ch):
    if ss[-1:] == ch:
        ss = ss[0:-1]
        s0 = remove_last_from_string_recursive(ss, ch)
        return s0
    return ss


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
        print("  " + m)
    # Read local directory
    dir_dirs = next(os.walk(local_path))[1]
    dir_files = next(os.walk(local_path))[2]
    dir_file_det = []
    for df in dir_files:
        fn = local_path + "/" + df
        # mtime = os.path.getmtime(fn)
        # mdate = datetime.datetime.fromtimestamp(mtime)
        dir_file_det.append((df, fn, os.path.getsize(fn), os.path.getmtime(fn)))
    if dir_file_det:
        printlog(2, "Local files: " + local_path)
        for (dfd_fn0, dfd_fn, dfd_size, dfd_mdate) in dir_file_det:
            print("  " + dfd_fn0 + " : " + dfd_fn + " : " + str(dfd_mdate) + " : " + str(dfd_size))
    if dir_dirs:
        printlog(2, "Local directories: " + local_path)
        for d in dir_dirs:
            print("  " + d)
    if mode == "backup":
        # Part Ia. compare local to ftp and update FTP files or upload (if not ye on FTP)
        uploadlist = []
        for sfn0, sfn, ssize, sts in dir_file_det:
            matched = False
            sizeratio = 1
            for ffn0, ffn, fsize, fmdate in ftp_files:
                fts = fmdate.timestamp()
                if sfn0 == senc.fernet_decrypt(ffn0):
                    try:
                        sizeratio = abs((int(fsize) - 30) / int(ssize) - 1)
                    except:
                        sizeratio = 0
                    matched = True
                    break
            if (matched and sts > fts) or (not matched) or (matched and sizeratio > 0.2 and ssize > 1000):
                if (matched and sizeratio > 0.2 and ssize > 1000):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Incomplete file on FTP: adding" + sfn0 + str(source_ts) + " to upload queue")
                    printlog(1, "   Size on FTP , Size on source, Ratio:" + str(fsize) + " " + str(ssize) + " " + str(sizeratio))
                    sftp.delete(ffn)
                elif (matched and sts > fts):
                    source_ts = datetime.datetime.fromtimestamp(sts)
                    printlog(1, "Replacment because of newer: adding " + sfn0 + str(source_ts) + " to upload queue")
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
                if sfn0 == senc.fernet_decrypt(ffn0):
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
                if senc.fernet_decrypt(ffn0) == sfn0:
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
                if senc.fernet_decrypt(ffn0) == sfn0:
                    matched = True
                    break
            if not matched:
                printlog(1, sfn0 + " not found on FTP, deleting locally ...")
                os.remove(sfn)
    if mode == "backup":
        # Part IIIa. compare FTP dirs to local dirs and delete dirs on FTP which are not local
        for fd0 in ftp_dirs:
            fd00 = senc.fernet_decrypt(fd0)
            if fd00 == -1 or fd00 not in dir_dirs:
                printlog(1, "Directory " + ftp_path + "/" + fd0 + " not found locally, deleting from FTP ...")
                deleteFTPDirectoryRecursive(sftp, ftp_path + "/" + fd0)
    elif mode == "restore":
        # Part IIIb. compare local dirs to FTP dirs and delete local dirs which are not on FTP
        for sd0 in dir_dirs:
            matched = False
            for fd0 in ftp_dirs:
                fd00 = senc.fernet_decrypt(fd0)
                if sd0 == fd00:
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
            dd0 = senc.fernet_encrypt(dd)
            for ff in ftp_dirs:
                if senc.fernet_decrypt(ff) == dd:
                    dd0 = ff
                    break
            SyncLocalDir(sftp, senc, local_path + "/" + dd, ftp_path + "/" + dd0, recursion + 1, mode=mode)
        elif mode == "restore":
            SyncLocalDir(sftp, senc, local_path + "/" + senc.fernet_decrypt(dd), ftp_path + "/" + dd, recursion + 1, mode=mode)


def printlog(level, msg):
    global OUTPUT_VERBOSITY
    # level 0: critical , level 2: all
    if level <= OUTPUT_VERBOSITY:
        if level == 0:
            msg = "!ERROR: " + msg
        print(msg)


if __name__ == "__main__":
    # stasftp --local /path/to/source --remote /path/on/ftp --mode backup/restore --config /path/to/config
    parser = argparse.ArgumentParser(description='AES encrypted FTP backup/restore tool')
    parser.add_argument('-l', "--local", help='/path/to/local_directory', type=str)
    parser.add_argument('-r', "--remote", help='/remote/directory/on_FTP_server', type=str)
    parser.add_argument('-m', "--mode", help='backup <-> restore', type=str)
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
        STASCFGPATH = ("/media/nfs/NFS_Projekte/GIT/STAS/data/")
    else:
        STASCFGPATH = args.mode
    try:
        stasftpcfg = configparser.ConfigParser()
        stasftpcfg.read(STASCFGPATH + "stasftp.cfg")
        FTP_HOST = stasftpcfg["CONFIG"]["FTP_HOST"]
        FTP_USER = stasftpcfg["CONFIG"]["FTP_USER"]
        FTP_PASSWD = stasftpcfg["CONFIG"]["FTP_PASSWD"]
        # KEY_PASSWD = stasftpcfg["CONFIG"]["KEY_PASSWD"]
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
    sftp = StasFTP(FTP_HOST, FTP_USER, FTP_PASSWD)
    if sftp.FTP_STATUS == -1:
        printlog(0, sftp.FTP_ERROR + ": FTP connection error, exiting ...")
        sys.exit()
    else:
        printlog(2, "FTP '" + sftp.FTP_HOST + "' connected!")
    senc = StasEncrypt(KEY_PASSWD, sftp)
    SyncLocalDir(sftp, senc, SOURCEPATH, FTP_PATH, 1, mode=STASMODE)

# to do
# fernet also bei download, allen vergleichen und directories
