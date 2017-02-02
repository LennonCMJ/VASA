#!/usr/bin/env python

import subprocess

def nessusScan():

    try:
        os.mkdir("Nessus")
    except:
        pass

    print ('[+] Generating Nessus XML file')
    NESSUS = \
        "nmap -sS -p- -iL './targets.txt' -oX './Nessus/nessus_nmap.xml'"
    nessus_result = subprocess.check_output(NESSUS, shell=True)