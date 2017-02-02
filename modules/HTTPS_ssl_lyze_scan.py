#!/usr/bin/env python

import subprocess

def sslyze_scan(ip_address, port):
    print ('\t\tPerforming SSLYZE Scan on IP: %s' %ip_address)
    SSLYZE_TEST = \
        'sslyze --regular %s:%s >> ./%s/SSL/%s_%s_sslyze.txt' \
        % (ip_address, port, ip_address, ip_address, port)
    SSLYZE_RESULT = subprocess.check_output(SSLYZE_TEST, shell=True)
   

def main(ip_address,port):
	print ('\t\tPreparing to do SSLyze scan..')
	sslyze_scan(ip_address,port)