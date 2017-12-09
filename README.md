STASFTP

STASFTP is built upon python ftplib and syncs local files/directies with remote directories on an FTP (via FTPS), additionally it encrypts/decrypts these files on-the-fly (prior to upload/after download) without using addtl. 
diskspace usually. In case files cannot be encrypted due to lack of memory (pycrypto needs lots of RAM), these files are uploaded unencrypted!!
Usage:

stasftp --local /path/to/sourcedir --remote /path/on/ftp --mode backup/restore
        --log logfile_in_~/.stasftp/log --exclude excludefile_in_~/.stasftp/exclude
stasftp -l /path/to/sourcedir -r /path/on/ftp --m backup/restore                         
        -o logfile_in_~/.stasftp/log -e excludefile_in_~/.stasftp/exclude

stasftp default dir: ~/.stasftp -> will be created on first run

excludefile contains a list of all directory that should not be synced

if mode == backup:
        backups --local to --remote doing in-memory on-the-fly encryption
if mode == restore:
        restore --remote to --local doing in-memory on-the-fly encryptio

Keys / Ciphers:

For filenames Vignere-encryption is used, for files AES.
Keys are either autogenerated and saved in ~/.stasftp/keys/AES_key and ~/.stasftz/keys/VIGNERE_key
(if not yet existant) or loaded from this file.

!!! ONCE THIS FILES ARE GENERATED STORE THEM ON A SAFE PLACE AS WITHOUT THEM ENCRYPTED FILES
!!! CANNOT BE DECRYPTED ANYMORE!!!

Directory/file structure:

~/.stasftp/config/stasftp.cfg	config file	
~/.stasftp/exclude/			exclude file location	
~/.stasftp/keys/			keys are stored here (AES & VIGENERE)
~/.stasftp/log			directory for log files
~/.stasftp/tmp			dir for temp. files, do not touch/change		

Licensed under the GPLv3

