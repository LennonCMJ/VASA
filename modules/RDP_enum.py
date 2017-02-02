#!/usr/bin/env python

import subprocess

def rdp_enumeration(ip_address, port):
    print ('\t\tPerforming RDP enumeration for IP: %s' %ip_address)
    RDP_ENUM = \
        'nmap -p%s --script rdp-enum-encryption %s -oA ./%s/RDP/%s_nmap_rdp_enum.nmap %s' \
        % (port, ip_address, ip_address, ip_address, ip_address)
    RDP_ENUM_RESULT = subprocess.check_output(RDP_ENUM, shell=True)


def main(ip_address,port):
	print ('\t\tPreparing enumeration for RDP..')
	rdp_enumeration(ip_address,port)
