#!/usr/bin/env python

import subprocess


def banner_grab_https(ip_address, port):

    print ('Grabbing SSL Certificate for IP: %s' %ip_address)

  # http://www.mail-archive.com/openssl-users@openssl.org/msg02937.html

    HTTPS_GRAB = \
        "(echo 'GET /'; sleep 10) | openssl s_client -connect %s:443 >> ./%s/SSL/%s_%s_sslcert.txt" \
        % (ip_address, ip_address, ip_address, port)
    HTTPS_RESULT = subprocess.check_output(HTTPS_GRAB, shell=True)


def main(ip_address,port):
	banner_grab_https(ip_address,port)