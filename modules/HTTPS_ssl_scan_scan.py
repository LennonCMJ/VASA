#!/usr/bin/env python

import subprocess

def sslscan_scan(ip_address, port):
    print ('\t\tPerforming SSLSCAN scan on IP: %s' %ip_address)
    SSLSCAN_TEST= \
        'sslscan --xml=./%s/SSL/%s_%s_sslscan.xml %s > /dev/null' \
        % (ip_address, ip_address, port, ip_address)
    SSLSCAN_TEST = subprocess.check_output(SSLSCAN_TEST, shell=True)


def main(ip_address,port):
	print ('\t\tPreparing to do SSLscan scan..')
	sslscan_scan(ip_address,port)