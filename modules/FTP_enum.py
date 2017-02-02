#!/usr/bin/env python

import subprocess

def ftp_Enum(ip_address, port):

    print ('Performing FTP Scan on IP Address : %s \n' % ip_address)
    FTPSCAN = \
        'nmap -sV -Pn -vv -p %s  --script=ftp-anon,ftp-proftpd-backdoor,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor -oA ./%s/FTP/%s_nmap_ftp.nmap -T4 %s' \
        % (port, ip_address, ip_address, ip_address)
    FTPSCAN = subprocess.check_output(FTPSCAN, shell=True)


def main(ip_address,port):
    print ('\t\tPreparing for FTP enumeration..')
    ftp_Enum(ip_address,port)