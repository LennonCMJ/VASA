#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket
import os

def banner_grab_http(ip_address, port):
    print ('\t\tGrabbing HTTP Banner for IP: %s' %ip_address)
    host = 'google.com'  # any site name or IP address
    port_1 = int(port)
    addr = (ip_address, port_1)
    s = socket.socket()
    s.connect(addr)
    s.send('GET / HTTP/1.0\r\nHost: ' + host + '''\r
\r
''')
    return s.recv(1024)

def main(ip_address, port):
    output = banner_grab_http(ip_address, port)
	# Save output into file under respective IP addresses under HTTP directory
    f = open('./%s/HTTP/%s_%s_banner.txt' % (ip_address, ip_address, port), 'w')
    f.write(output)
    f.close()