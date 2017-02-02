#!/usr/bin/env python
# -*- coding: utf-8 -*-

#########################################################################################
# Title : Recon scanner / recon and enumeration script                                  #
#########################################################################################

import os
import re
import sys
import time
import socket
import logging
import fileinput
import subprocess
import multiprocessing
from functools import partial
from datetime import datetime
from netaddr import IPNetwork as IPN
from multiprocessing import Process, Queue, Pool


### Global variable for 'root' directory (<path>/NetworkScan) ###
rootDir = ""

def nmapScan(ip_address):
    global rootDir

    # Insert filepath to be able to import modules from /modules directory
    sys.path.insert(0,rootDir.replace('NetworkScan','modules'))


    # Make directory, categorizing by target's IP address
    try:
        os.mkdir(ip_address)
    except:
        pass

    # Make a '/NMAP' directory under the target's IP directory
    try:
        os.mkdir("%s/NMAP"%ip_address)
    except:
        pass

    ip_address = ip_address.strip()
    print ('\n[+] Running general TCP/UDP nmap scans for ' + ip_address)
    serv_dict = {}

    # Nmap scan options and parameters, ouput file will be saved under '<target IP>/NMAP' directory
    TCPSCAN = "nmap -PN -oN './%s/NMAP/%s.nmap' -oX './%s/NMAP/%s_nmap_scan_import.xml' %s" %(ip_address, ip_address, ip_address, ip_address, ip_address)

    # UDP scan disabled for now 
    # UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN './%s/%sU.nmap' -oX './%s/%sU_nmap_scan_import.xml' %s" % (ip_address, ip_address, ip_address, ip_address, ip_address)

    # Results of Nmap scan
    results = subprocess.check_output(TCPSCAN, shell=True)
    lines = results.split('\n')

    # Looping through nmap results, line by line
    for line in lines:
        ports = []
        line = line.strip()

        if 'tcp' in line and 'open' in line and not 'Discovered' in line:
            while '  ' in line:
                line = line.replace('  ', ' ')
            linesplit = line.split(' ')

            # Grab the service name
            service = linesplit[2]

            # Grab the port/proto
            port = line.split(' ')[0]

            if service in serv_dict:
                # If the service is already in the dict, grab the port list
                ports = serv_dict[service]  

            ports.append(port)

            # Add service to the dictionary along with the associated port(2)
            serv_dict[service] = ports  

    #Go through the service dictionary to call additional targeted enumeration functions
    for serv in serv_dict:
        ports = serv_dict[serv]

        
        # Get (module) files in directory, then run the files associated with protocol
        files = os.listdir(rootDir.replace('NetworkScan','modules'))

        mod = ''
        output = ''

        
        for port in ports:
            port = port.split('/')[0]
            print ("\n[+] %s found --> %s "%(serv.upper(),ip_address))

            # Get (module) files in directory, then run the files associated with protocol
            files = os.listdir(rootDir.replace('NetworkScan','modules'))

                # Loop through directory for each module file
            for file in files:
                try:
                    if '.pyc' not in file:
                        
                        servFile = serv.upper() + '_'
                        # If module file starts with <protocol>
                        if servFile in file:
                            # Make directory <protocol> under target IP address directory
                            try:
                                # Rename HTTPS protocol to SSL
                                if serv == 'ssl/http' or 'https' in serv:
                                    os.mkdir("%s/%s"%(ip_address,'SSL'))
                                else:
                                    os.mkdir("%s/%s"%(ip_address,serv.upper()))
                            except:
                                pass

                            mod = file.replace('.py','')
                            
                            # Import variable module
                            newmod = __import__(mod)

                            # Execute module's main function
                            newmod.main(ip_address, port)

                except:
                    pass



    print ('\n[+] TCP/UDP Nmap scans completed for ' + ip_address)
    

### Initialize scan ###
def init_targets(path):
    ip_to_scan = []

    CIDRcheck = ""

    # Reading targets.txt
    with open(path,'r') as f:
        ipList = f.readlines()

    # Loop through IP addresses
    for scanip in ipList:
        
        # Check if IP provided has CIDR notation
        try:
            CIDRcheck = str(re.search('/\d{2}',scanip).group(0))
        except:
            pass 

        if not CIDRcheck:
            scanip = scanip.replace('\n','')
            ip_to_scan.append(scanip)

        else:
            # If CIDR notation is present, get range of IPs and scan each of them inidividually
            for ip in IPN(scanip):
                ip_to_scan.append(str(ip))


    # Multiprocessing
    pool = multiprocessing.Pool(processes=2)
    func = partial(nmapScan)
    pool.map(func, ip_to_scan)
    pool.close()
    pool.join()


### Targets.txt file not found, provided with choices ###
def targetsChoice(choice):
    wrong = 0
    if '1' in choice:
        targets_file = raw_input('\n\tPath to targets.txt file ==> ')
        while 1:
            if wrong:
                print ('\n\tINVALID Path !')
                targets_file = raw_input('\n\tPath to targets.txt file ==> ')
                print (targets_file)

            try:
                os.rename(targets_file,'./targets.txt')
                break
            except:
                wrong = 1


        init_targets('./targets.txt')

    elif '2' in choice:
        targets = []

        target = raw_input('\n\tEnter/Paste IP here ==> ')
        targets.append(target)

        while 1:
            target = raw_input('\tEnter IP (type \'q\' to quit) ==> ')
            if ('q' or 'Q') in target:
                break
            else:
                if target not in targets:
                    targets.append(target)

        with open('./targets.txt','w') as f:
            for target in targets:
                target = target.strip()
                if target:
                    f.write(target+'\n')



        init_targets('./targets.txt')

    else:
        return "invalid"

### Call generate SSL summary module ###
def gen_ssl_summary():
    import SSL_report_gen
    global rootDir
    SSL_report_gen.gen_ssl_summary(rootDir)


### Main function ###
def main():
    global rootDir

    ### Mainly prinitng out information for User ###

    print ('[+] Making directory %s/NetworkScan'%os.getcwd())

    try:
        os.mkdir('NetworkScan')
        os.chdir('NetworkScan')
    except:
        os.chdir('NetworkScan')


    print ('[+] Current Directory: %s'%os.getcwd())
    rootDir = os.getcwd()
    print ('[+] Output files in: %s/<IP address>'%(os.getcwd()))

    try:
        try:
            os.rename('../targets.txt', './targets.txt')
        except:
            open('./targets.txt')


        path = "./targets.txt"


        print ('\n[*] Running scans from targets.txt...')
        init_targets(path)
    
    except:
        print ('\n[!] tagets.txt file does not exist...\n')
        print ('-----------------------------\n1. Enter path to targets.txt\n2. Enter IP manually\n-----------------------------')

        choiceCheck = 'valid'
        while choiceCheck:
            choice = raw_input('Enter choice ==> ')
            choiceCheck = targetsChoice(choice)
    
    # Generate SSL summary after all scans are completed
    gen_ssl_summary()


if __name__ == '__main__':
    main()
