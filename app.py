from tika import parser # pip install tika
import socket
import re
from ipwhois import IPWhois as whois
import json

raw = parser.from_file('Responses.pdf')
parsed = raw['content']
print()
ipAddresses = []

def checkIpForDesiredPort(ip):
    #ip = socket.gethostbyname(ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    portsToScan = [22,80,443,21,23,3389]
    print("checking ports for ", ip)
    ports = {"open":[],"closed":[]}
    hasOpen = False
    for port in portsToScan:
        
        result = sock.connect_ex((ip,port))
        if result == 0:
            print("Port is open")
            hasOpen = True
            ports["open"].append(port)
        else:
            print ("Port is not open")
            ports["closed"].append(port)
    if hasOpen:
        generateWhois(ip, ports)
    sock.close()
def generateWhois(ip, ports):
    obj = whois(ip)
    res = json.loads(json.dumps(obj.lookup_whois(),indent=2))
    res.update(ports)
    res = json.dumps(res,indent=2)
    with open(ip+'.json', "w") as f: 
        f.write(res) 
        f.close()
    #print(res)
def find_matching_ip_addresses(string):
    pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    matches = re.findall(pattern, string)
    return matches

ipAddresses = find_matching_ip_addresses(parsed)

for ip in ipAddresses:
    try:
        checkIpForDesiredPort(ip)
    except socket.gaierror:
        print("unable to check that: "+ip)

