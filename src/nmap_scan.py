'''
Nmap scan commons HTTP port and report generator.

Author: Glaudson Ocampos <glaudson@votex-ai.com.br>
'''

import sys, os
import signal

from libnmap.parser import NmapParser
from libnmap.process import NmapProcess



def run_nmap(target):
    targets=[]
    
    f = open(target,"r")
    for line in f.readlines():
        ip = line.replace("\n","")
        targets.append(ip)
    f.close()

    print("Running nmap on target from: " + target)
    nm = NmapProcess(targets=targets, options="-Pn -p 80,443,8080")
    rc = nm.run()
    f = open('portscans/nmap_http2.xml','w')
    if nm.rc == 0:
        #print(nm.stdout)
        f.write(nm.stdout)
    else:
        #print(nm.stderr)    
        f.write(nm.stderr)
    
    f.close()
    print("Nmap finished.")
    
    

def gen_report(report_file):
    nmap_report = NmapParser.parse_fromfile(report_file)
    print("Nmap scan summary:" + "{0}".format(nmap_report.summary))
    
    
    print("Scanned hosts: ")
    for scanned_host in nmap_report.hosts:
        #print("\t+" + str(scanned_host.address))
        for po in scanned_host.get_open_ports():
            #print("\t\t+ " + str(po[0]))
            if str(po[0]) == "80":
                print("http://" + str(scanned_host.address) + "/")
            if str(po[0]) == "8080":
                print("http://" + str(scanned_host.address) + ":8080/")
            if str(po[0]) == "443":
                print("https://" + str(scanned_host.address) + "/")

def handler(signum, frame):
    print("\n\nStop execution...", signum);
    sys.exit(0)
    

def show_ed209():
    f = open("./ed209.asc","r")
    print(f.read())
    f.close()     

def show_help():
    print("Vortex-AI - ED-209 - Nmap ips.")
    print("http://www.vortex-ai.com.br/\n")
    show_ed209()
    print("Usage: python3  " + __file__ + " <ips.txt>\n")
    print("Example:\n")
    print("python3 " + __file__ + " ips.txt")
    
    

def main(args):
    signal.signal(signal.SIGINT, handler)
    if args is None:
        show_help()
    else:
        run_nmap(args[0])
        gen_report('portscans/nmap_http2.xml')
        
if __name__ == '__main__':
    if len(sys.argv) == 1:
        show_help()
    else:
        main(sys.argv[1:])
    




