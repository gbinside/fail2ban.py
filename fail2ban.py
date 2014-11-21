#!/usr/bin/env python
#sudo cat /var/log/auth.log | grep "failed - POSSIBLE BREAK-IN ATTEMPT!"
from subprocess import Popen, PIPE
import sys
import re

#list of ip excluded from ban
NOBANIP = ('127.0.0.1',)
THRESHOLD = 10
breakin = re.compile(r'\[((\d+\.){3}\d+)\] failed - POSSIBLE BREAK-IN ATTEMPT',re.I)
iptables = re.compile(r'DROP\s*all\s*--\s*((?:\d+\.){3}\d+)\s*0.0.0.0/0', re.I)


def main():
    dizio = dict()
    for line in open('/var/log/auth.log'):
        match = breakin.findall(line)
        if match:
            if match[0][0] not in dizio:
                dizio[match[0][0]] = 0
            dizio[match[0][0]] += 1
    for x in NOBANIP:
        if x in dizio:
            del dizio[x]
    if dizio:
        output = Popen(["iptables", "-L", "INPUT", "-n"], stdout=PIPE).communicate()[0]
        alreadybanned = iptables.findall(output)
        dizio =  dict([(x,y) for x,y in dizio.items() if y>THRESHOLD and x not in alreadybanned]) 
    
        for k in dizio:
            output = Popen(["iptables", "-A", "INPUT", "-s", k, "-j", "DROP"], stdout=PIPE).communicate()[0]            
    return 0    

if __name__ == '__main__':
    sys.exit(main())

